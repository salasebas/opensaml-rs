//! Cut one element out of a document as standalone XML.

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::PrefixDeclaration;
use quick_xml::Reader;

use crate::error::SamlError;

struct Declaration {
    /// Declared prefix. Empty for the default namespace.
    prefix: String,
    /// Namespace URI as written in the document, safe inside double quotes.
    value: String,
}

/// Return the element at `start..end` of `xml` as standalone XML.
///
/// A namespace prefix the element or a descendant uses in an element or
/// attribute name, and that only an ancestor declares, is declared on the
/// returned element. An element that declares every prefix it uses is
/// returned unchanged.
///
/// # Errors
///
/// Returns [`SamlError::Xml`] when `xml` is malformed or `start..end` is not
/// one element of it.
pub(crate) fn standalone_element(xml: &str, start: usize, end: usize) -> Result<String, SamlError> {
    let element = xml
        .get(start..end)
        .ok_or_else(|| SamlError::Xml("element is outside the document".into()))?;
    let inherited = inherited_declarations(xml, start)?;
    if inherited.is_empty() {
        return Ok(element.to_string());
    }
    let name_end = element
        .find(|ch: char| ch.is_ascii_whitespace() || ch == '/' || ch == '>')
        .ok_or_else(|| SamlError::Xml("element start tag is incomplete".into()))?;
    let mut standalone = String::with_capacity(element.len());
    standalone.push_str(&element[..name_end]);
    for declaration in &inherited {
        standalone.push_str(" xmlns");
        if !declaration.prefix.is_empty() {
            standalone.push(':');
            standalone.push_str(&declaration.prefix);
        }
        standalone.push_str("=\"");
        standalone.push_str(&declaration.value);
        standalone.push('"');
    }
    standalone.push_str(&element[name_end..]);
    Ok(standalone)
}

/// Ancestor declarations the element starting at `start` relies on.
fn inherited_declarations(xml: &str, start: usize) -> Result<Vec<Declaration>, SamlError> {
    let mut reader = Reader::from_str(xml);
    let mut scopes: Vec<Vec<Declaration>> = Vec::new();
    let mut element_depth = None;
    let mut inherited = Vec::new();
    loop {
        let before = reader.buffer_position() as usize;
        let event = reader
            .read_event()
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::Start(element) => {
                if element_depth.is_none() && (before..after).contains(&start) {
                    element_depth = Some(scopes.len());
                }
                scopes.push(declarations(&element)?);
                if let Some(depth) = element_depth {
                    collect_inherited(&element, &scopes, depth, &mut inherited)?;
                }
            }
            Event::Empty(element) => {
                let is_element = element_depth.is_none() && (before..after).contains(&start);
                if is_element {
                    element_depth = Some(scopes.len());
                }
                scopes.push(declarations(&element)?);
                if let Some(depth) = element_depth {
                    collect_inherited(&element, &scopes, depth, &mut inherited)?;
                }
                scopes.pop();
                if is_element {
                    return Ok(inherited);
                }
            }
            Event::End(_) => {
                scopes.pop();
                if element_depth == Some(scopes.len()) {
                    return Ok(inherited);
                }
            }
            Event::DocType(_) => {
                return Err(SamlError::Xml("DOCTYPE is not allowed".into()));
            }
            Event::Eof => {
                return Err(SamlError::Xml("element is outside the document".into()));
            }
            Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => {}
        }
    }
}

fn declarations(element: &BytesStart<'_>) -> Result<Vec<Declaration>, SamlError> {
    let mut declared = Vec::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
        let prefix = match attribute.key.as_namespace_binding() {
            Some(PrefixDeclaration::Default) => String::new(),
            Some(PrefixDeclaration::Named(prefix)) => prefix.to_string(),
            None => continue,
        };
        declared.push(Declaration {
            prefix,
            value: attribute.value.replace('"', "&quot;"),
        });
    }
    Ok(declared)
}

/// Record each prefix `element` uses that `scopes[depth..]` does not declare.
fn collect_inherited(
    element: &BytesStart<'_>,
    scopes: &[Vec<Declaration>],
    depth: usize,
    inherited: &mut Vec<Declaration>,
) -> Result<(), SamlError> {
    let element_prefix = match element.name().prefix() {
        Some(prefix) => prefix.into_inner(),
        None => "",
    };
    let mut used = vec![element_prefix];
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| SamlError::Xml(err.to_string()))?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        if let Some(prefix) = attribute.key.prefix() {
            used.push(prefix.into_inner());
        }
    }
    let (ancestors, local) = scopes.split_at(depth);
    for prefix in used {
        if prefix == "xml" || declares(local, prefix).is_some() {
            continue;
        }
        if inherited.iter().any(|known| known.prefix == prefix) {
            continue;
        }
        if let Some(declaration) = declares(ancestors, prefix) {
            if !declaration.value.is_empty() {
                inherited.push(Declaration {
                    prefix: declaration.prefix.clone(),
                    value: declaration.value.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Innermost declaration of `prefix` in `scopes`.
fn declares<'a>(scopes: &'a [Vec<Declaration>], prefix: &str) -> Option<&'a Declaration> {
    scopes
        .iter()
        .rev()
        .flat_map(|scope| scope.iter().rev())
        .find(|declaration| declaration.prefix == prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::dom;

    fn first_grandchild(xml: &str) -> Result<String, SamlError> {
        let document = dom::parse(xml)?;
        let node = document
            .root
            .children
            .first()
            .and_then(|child| child.children.first())
            .ok_or_else(|| SamlError::Xml("fixture has no grandchild".into()))?;
        standalone_element(xml, node.start, node.end)
    }

    #[test]
    fn an_element_that_declares_its_prefixes_is_unchanged() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:a" xmlns:b="urn:b"><a:Mid><b:Leaf xmlns:b="urn:inner" b:id="1"/></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<b:Leaf xmlns:b="urn:inner" b:id="1"/>"#
        );
        Ok(())
    }

    #[test]
    fn prefixes_declared_on_ancestors_are_declared_on_the_element() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:unused"><a:Mid xmlns:c="urn:c"><b:Leaf c:id="1"><a:Inner/></b:Leaf></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<b:Leaf xmlns:b="urn:b" xmlns:c="urn:c" xmlns:a="urn:a" c:id="1"><a:Inner/></b:Leaf>"#
        );
        Ok(())
    }

    #[test]
    fn an_inherited_default_namespace_is_declared_on_the_element() -> Result<(), SamlError> {
        let xml = r#"<Root xmlns="urn:default"><Mid><Leaf id="1">text</Leaf></Mid></Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<Leaf xmlns="urn:default" id="1">text</Leaf>"#
        );
        Ok(())
    }

    #[test]
    fn the_innermost_ancestor_declaration_wins() -> Result<(), SamlError> {
        let xml = r#"<a:Root xmlns:a="urn:outer"><a:Mid xmlns:a='urn:"inner"'><a:Leaf/></a:Mid></a:Root>"#;
        assert_eq!(
            first_grandchild(xml)?,
            r#"<a:Leaf xmlns:a="urn:&quot;inner&quot;"/>"#
        );
        Ok(())
    }

    #[test]
    fn a_span_that_is_not_an_element_is_rejected() {
        let xml = r#"<a:Root xmlns:a="urn:a">text</a:Root>"#;
        assert!(matches!(
            standalone_element(xml, xml.len(), xml.len()),
            Err(SamlError::Xml(_))
        ));
    }
}
