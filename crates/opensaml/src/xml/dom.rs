//! Minimal read-only XML DOM built on quick-xml.
//!
//! Nodes carry their source byte span so the extractor can return the exact
//! original substring for `context` fields (avoiding any re-serialisation /
//! canonicalisation concerns — verification is delegated to bergshamra).

use crate::error::OpenSamlError;
use quick_xml::events::Event;
use quick_xml::name::QName;
use quick_xml::Reader;

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

fn read_attrs(e: &quick_xml::events::BytesStart) -> Result<Vec<(String, String)>, OpenSamlError> {
    let mut out = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|err| OpenSamlError::Xml(err.to_string()))?;
        let key = local_name_str(attr.key);
        let value = attr
            .unescape_value()
            .map_err(|err| OpenSamlError::Xml(err.to_string()))?
            .into_owned();
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

/// Parse `xml` into a [`Document`].
pub fn parse(xml: &str) -> Result<Document, OpenSamlError> {
    let root = parse_roots(xml)?
        .into_iter()
        .next()
        .ok_or_else(|| OpenSamlError::Xml("no document element".into()))?;
    Ok(Document { root })
}

/// Parse every top-level element (used to detect multiple root descriptors).
pub fn parse_roots(xml: &str) -> Result<Vec<Node>, OpenSamlError> {
    let mut reader = Reader::from_str(xml);
    let bytes = xml.as_bytes();
    let mut stack: Vec<Node> = Vec::new();
    let mut roots: Vec<Node> = Vec::new();

    loop {
        let before = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|err| OpenSamlError::Xml(err.to_string()))?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::Start(e) => {
                let start = find_lt(bytes, before, after);
                stack.push(Node {
                    local_name: local_name_str(e.name()),
                    attrs: read_attrs(&e)?,
                    children: Vec::new(),
                    text: String::new(),
                    start,
                    end: 0,
                });
            }
            Event::Empty(e) => {
                let start = find_lt(bytes, before, after);
                let node = Node {
                    local_name: local_name_str(e.name()),
                    attrs: read_attrs(&e)?,
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
                    let txt = e
                        .unescape()
                        .map_err(|err| OpenSamlError::Xml(err.to_string()))?;
                    top.text.push_str(&txt);
                }
            }
            Event::CData(e) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(&e.into_inner()));
                }
            }
            // Hardening (adapted from openauth-saml): reject DTDs so the parser
            // can never be steered into entity-expansion / XXE territory.
            Event::DocType(_) => {
                return Err(OpenSamlError::Xml("DOCTYPE is not allowed".into()));
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
    fn parses_root_and_attrs() -> Result<(), OpenSamlError> {
        let doc = parse("<a:Root xmlns:a=\"urn:x\" id=\"1\"><b>hi</b></a:Root>")?;
        assert_eq!(doc.root.local_name, "Root");
        assert_eq!(doc.root.attr("id"), Some("1"));
        assert_eq!(doc.root.children.len(), 1);
        assert_eq!(doc.root.children[0].text, "hi");
        Ok(())
    }
}
