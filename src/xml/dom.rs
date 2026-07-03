//! Minimal read-only XML DOM built on quick-xml.
//!
//! Nodes carry their source byte span so the extractor can return the exact
//! original substring for `context` fields (avoiding any re-serialisation /
//! canonicalisation concerns — verification is delegated to bergshamra).

use crate::error::SamlError;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, Event};
use quick_xml::name::QName;
use quick_xml::{Reader, XmlVersion};

/// Default maximum XML bytes accepted before DOM construction.
pub const DEFAULT_XML_MAX_BYTES: usize = 1024 * 1024;
/// Default maximum nested element depth accepted before DOM construction.
pub const DEFAULT_XML_MAX_DEPTH: usize = 1024;
/// Default maximum element nodes accepted before DOM construction.
pub const DEFAULT_XML_MAX_NODES: usize = 50_000;
/// Default maximum attributes accepted on one element.
pub const DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT: usize = 64;
/// Default maximum decoded bytes accepted for one attribute value.
pub const DEFAULT_XML_MAX_ATTRIBUTE_VALUE_BYTES: usize = 16 * 1024;
/// Default maximum decoded direct text bytes accepted for one element.
pub const DEFAULT_XML_MAX_TEXT_BYTES: usize = DEFAULT_XML_MAX_BYTES;

const XML_LIMIT_EXCEEDED: &str = "ERR_XML_LIMIT_EXCEEDED";

/// Resource limits enforced while parsing XML into the local DOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlLimits {
    /// Maximum input bytes accepted before parsing.
    pub max_bytes: usize,
    /// Maximum nested element depth.
    pub max_depth: usize,
    /// Maximum element nodes in the document.
    pub max_nodes: usize,
    /// Maximum attributes on one element.
    pub max_attributes_per_element: usize,
    /// Maximum decoded bytes for one attribute value.
    pub max_attribute_value_bytes: usize,
    /// Maximum decoded direct text bytes for one element.
    pub max_text_bytes: usize,
}

impl XmlLimits {
    /// Disable parser resource limits. Intended only for trusted local input.
    pub const fn unbounded() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_depth: usize::MAX,
            max_nodes: usize::MAX,
            max_attributes_per_element: usize::MAX,
            max_attribute_value_bytes: usize::MAX,
            max_text_bytes: usize::MAX,
        }
    }

    pub(crate) fn check_input_bytes(self, len: usize) -> Result<(), SamlError> {
        if len > self.max_bytes {
            return Err(limit_exceeded("max XML bytes", self.max_bytes));
        }
        Ok(())
    }
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_XML_MAX_BYTES,
            max_depth: DEFAULT_XML_MAX_DEPTH,
            max_nodes: DEFAULT_XML_MAX_NODES,
            max_attributes_per_element: DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT,
            max_attribute_value_bytes: DEFAULT_XML_MAX_ATTRIBUTE_VALUE_BYTES,
            max_text_bytes: DEFAULT_XML_MAX_TEXT_BYTES,
        }
    }
}

/// A parsed XML element.
#[derive(Debug, Clone)]
pub struct Node {
    /// Local element name (namespace prefix stripped).
    pub local_name: String,
    /// Attributes as `(local-name, unescaped-value)` pairs.
    pub attrs: Vec<(String, String)>,
    /// Child elements in document order.
    pub children: Vec<Node>,
    /// Concatenated direct text content (unescaped).
    pub text: String,
    /// Byte offset of the element's opening `<` in the source.
    pub start: usize,
    /// Byte offset just past the element's closing `>` in the source.
    pub end: usize,
}

impl Node {
    /// Look up an attribute by local name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed document (its single root element).
#[derive(Debug, Clone)]
pub struct Document {
    /// Document (root) element.
    pub root: Node,
}

fn local_name_str(name: QName) -> String {
    String::from_utf8_lossy(name.local_name().as_ref()).into_owned()
}

fn limit_exceeded(limit: &str, max: usize) -> SamlError {
    SamlError::Invalid(format!("{XML_LIMIT_EXCEEDED}: {limit} exceeded ({max})"))
}

fn checked_node_count(count: &mut usize, limits: XmlLimits) -> Result<(), SamlError> {
    *count = count
        .checked_add(1)
        .ok_or_else(|| limit_exceeded("max XML nodes", limits.max_nodes))?;
    if *count > limits.max_nodes {
        return Err(limit_exceeded("max XML nodes", limits.max_nodes));
    }
    Ok(())
}

fn check_depth(depth: usize, limits: XmlLimits) -> Result<(), SamlError> {
    if depth > limits.max_depth {
        return Err(limit_exceeded("max XML depth", limits.max_depth));
    }
    Ok(())
}

fn checked_append_text(
    target: &mut String,
    text: &str,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    let next_len = target
        .len()
        .checked_add(text.len())
        .ok_or_else(|| limit_exceeded("max XML text bytes", limits.max_text_bytes))?;
    if next_len > limits.max_text_bytes {
        return Err(limit_exceeded("max XML text bytes", limits.max_text_bytes));
    }
    target.push_str(text);
    Ok(())
}

fn read_attrs(
    e: &quick_xml::events::BytesStart,
    limits: XmlLimits,
) -> Result<Vec<(String, String)>, SamlError> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        if out.len() >= limits.max_attributes_per_element {
            return Err(limit_exceeded(
                "max XML attributes per element",
                limits.max_attributes_per_element,
            ));
        }
        let attr = attr.map_err(|err| SamlError::Xml(err.to_string()))?;
        let key = local_name_str(attr.key);
        let value = attr
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, e.decoder())
            .map_err(|err| SamlError::Xml(err.to_string()))?
            .into_owned();
        if value.len() > limits.max_attribute_value_bytes {
            return Err(limit_exceeded(
                "max XML attribute value bytes",
                limits.max_attribute_value_bytes,
            ));
        }
        out.push((key, value));
    }
    Ok(out)
}

fn find_lt(bytes: &[u8], before: usize, after: usize) -> usize {
    bytes[before..after]
        .iter()
        .position(|&b| b == b'<')
        .map(|p| before + p)
        .unwrap_or(before)
}

fn push_child(stack: &mut [Node], roots: &mut Vec<Node>, node: Node) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => roots.push(node),
    }
}

fn push_general_ref(node: &mut Node, e: BytesRef, limits: XmlLimits) -> Result<(), SamlError> {
    if let Some(ch) = e
        .resolve_char_ref()
        .map_err(|err| SamlError::Xml(err.to_string()))?
    {
        let mut buf = [0; 4];
        checked_append_text(&mut node.text, ch.encode_utf8(&mut buf), limits)?;
        return Ok(());
    }

    let entity = e.decode().map_err(|err| SamlError::Xml(err.to_string()))?;
    let resolved = resolve_predefined_entity(&entity)
        .ok_or_else(|| SamlError::Xml(format!("unrecognized entity `{entity}`")))?;
    checked_append_text(&mut node.text, resolved, limits)?;
    Ok(())
}

/// Parse `xml` into a [`Document`].
pub fn parse(xml: &str) -> Result<Document, SamlError> {
    parse_with_limits(xml, XmlLimits::default())
}

/// Parse `xml` into a [`Document`] with explicit resource limits.
pub fn parse_with_limits(xml: &str, limits: XmlLimits) -> Result<Document, SamlError> {
    let root = parse_roots_with_limits(xml, limits)?
        .into_iter()
        .next()
        .ok_or_else(|| SamlError::Xml("no document element".into()))?;
    Ok(Document { root })
}

/// Parse every top-level element (used to detect multiple root descriptors).
pub fn parse_roots(xml: &str) -> Result<Vec<Node>, SamlError> {
    parse_roots_with_limits(xml, XmlLimits::default())
}

/// Parse every top-level element with explicit resource limits.
pub fn parse_roots_with_limits(xml: &str, limits: XmlLimits) -> Result<Vec<Node>, SamlError> {
    limits.check_input_bytes(xml.len())?;
    let mut reader = Reader::from_str(xml);
    let bytes = xml.as_bytes();
    let mut stack: Vec<Node> = Vec::new();
    let mut roots: Vec<Node> = Vec::new();
    let mut node_count = 0usize;

    loop {
        let before = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::Start(e) => {
                checked_node_count(&mut node_count, limits)?;
                check_depth(stack.len().saturating_add(1), limits)?;
                let start = find_lt(bytes, before, after);
                stack.push(Node {
                    local_name: local_name_str(e.name()),
                    attrs: read_attrs(&e, limits)?,
                    children: Vec::new(),
                    text: String::new(),
                    start,
                    end: 0,
                });
            }
            Event::Empty(e) => {
                checked_node_count(&mut node_count, limits)?;
                check_depth(stack.len().saturating_add(1), limits)?;
                let start = find_lt(bytes, before, after);
                let node = Node {
                    local_name: local_name_str(e.name()),
                    attrs: read_attrs(&e, limits)?,
                    children: Vec::new(),
                    text: String::new(),
                    start,
                    end: after,
                };
                push_child(&mut stack, &mut roots, node);
            }
            Event::End(_) => {
                if let Some(mut node) = stack.pop() {
                    node.end = after;
                    push_child(&mut stack, &mut roots, node);
                }
            }
            Event::Text(e) => {
                if let Some(top) = stack.last_mut() {
                    let txt = e.decode().map_err(|err| SamlError::Xml(err.to_string()))?;
                    checked_append_text(&mut top.text, &txt, limits)?;
                }
            }
            Event::CData(e) => {
                if let Some(top) = stack.last_mut() {
                    let inner = e.into_inner();
                    let text = String::from_utf8_lossy(&inner);
                    checked_append_text(&mut top.text, &text, limits)?;
                }
            }
            Event::GeneralRef(e) => {
                if let Some(top) = stack.last_mut() {
                    push_general_ref(top, e, limits)?;
                }
            }
            // Hardening (adapted from openauth-saml): reject DTDs so the parser
            // can never be steered into entity-expansion / XXE territory.
            Event::DocType(_) => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_doctype() {
        let xml = "<!DOCTYPE foo [<!ENTITY x \"y\">]><foo/>";
        assert!(parse(xml).is_err());
    }

    #[test]
    fn parses_root_and_attrs() -> Result<(), SamlError> {
        let doc = parse("<a:Root xmlns:a=\"urn:x\" id=\"1\"><b>hi</b></a:Root>")?;
        assert_eq!(doc.root.local_name, "Root");
        assert_eq!(doc.root.attr("id"), Some("1"));
        assert_eq!(doc.root.children.len(), 1);
        assert_eq!(doc.root.children[0].text, "hi");
        Ok(())
    }

    #[test]
    fn parses_escaped_attribute_and_text_values() -> Result<(), SamlError> {
        let doc = parse("<Root value=\"one &amp; two\"><Child>three &lt; four</Child></Root>")?;

        assert_eq!(doc.root.attr("value"), Some("one & two"));
        assert_eq!(doc.root.children[0].text, "three < four");
        Ok(())
    }

    fn limit_hit<T>(result: Result<T, SamlError>) -> bool {
        matches!(result, Err(SamlError::Invalid(message)) if message.contains(XML_LIMIT_EXCEEDED))
    }

    #[test]
    fn rejects_xml_over_byte_limit() {
        let limits = XmlLimits {
            max_bytes: 4,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<Root/>", limits)));
    }

    #[test]
    fn rejects_xml_over_depth_limit() {
        let limits = XmlLimits {
            max_depth: 2,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a><b><c/></b></a>", limits)));
    }

    #[test]
    fn rejects_xml_over_node_limit() {
        let limits = XmlLimits {
            max_nodes: 2,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a><b/><c/></a>", limits)));
    }

    #[test]
    fn rejects_xml_over_attribute_count_limit() {
        let limits = XmlLimits {
            max_attributes_per_element: 1,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a x=\"1\" y=\"2\"/>", limits)));
    }

    #[test]
    fn rejects_xml_over_default_attribute_count_limit() {
        let mut xml = String::from("<samlp:Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" attr{index}=\"value{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(parse(&xml)));
    }

    #[test]
    fn rejects_xml_over_default_namespace_declaration_count_limit() {
        let mut xml = String::from("<samlp:Response");
        for index in 0..=DEFAULT_XML_MAX_ATTRIBUTES_PER_ELEMENT {
            xml.push_str(&format!(" xmlns:p{index}=\"urn:test:{index}\""));
        }
        xml.push_str("/>");

        assert!(limit_hit(parse(&xml)));
    }

    #[test]
    fn duplicate_attribute_returns_xml_error() {
        let result = parse("<samlp:Response ID=\"first\" ID=\"second\"/>");

        assert!(matches!(result, Err(SamlError::Xml(_))));
    }

    #[test]
    fn rejects_xml_over_attribute_value_limit() {
        let limits = XmlLimits {
            max_attribute_value_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a x=\"1234\"/>", limits)));
    }

    #[test]
    fn rejects_xml_over_text_limit() {
        let limits = XmlLimits {
            max_text_bytes: 3,
            ..Default::default()
        };

        assert!(limit_hit(parse_with_limits("<a>1234</a>", limits)));
    }
}
