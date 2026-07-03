//! Structured XML writing helpers for generated SAML protocol XML.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

pub(crate) struct XmlWriter {
    inner: Writer<Vec<u8>>,
}

impl XmlWriter {
    pub(crate) fn new() -> Self {
        Self {
            inner: Writer::new(Vec::new()),
        }
    }

    pub(crate) fn finish(self) -> String {
        match String::from_utf8(self.inner.into_inner()) {
            Ok(xml) => xml,
            Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
        }
    }

    pub(crate) fn start<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Start(elem));
    }

    pub(crate) fn end(&mut self, name: &str) {
        self.write(Event::End(BytesEnd::new(name)));
    }

    pub(crate) fn empty<'a>(&mut self, name: &'a str, attrs: &[(&'a str, &'a str)]) {
        let elem = element(name, attrs);
        self.write(Event::Empty(elem));
    }

    pub(crate) fn text(&mut self, text: &str) {
        self.write(Event::Text(BytesText::new(text)));
    }

    pub(crate) fn text_element<'a>(
        &mut self,
        name: &'a str,
        attrs: &[(&'a str, &'a str)],
        text: &str,
    ) {
        self.start(name, attrs);
        self.text(text);
        self.end(name);
    }

    fn write<'a>(&mut self, event: Event<'a>) {
        // Vec-backed writes cannot fail; quick-xml keeps the Result because the
        // same API supports arbitrary std::io::Write targets.
        let _ = self.inner.write_event(event);
    }
}

fn element<'a>(name: &'a str, attrs: &[(&'a str, &'a str)]) -> BytesStart<'a> {
    let mut elem = BytesStart::new(name);
    for attr in attrs {
        elem.push_attribute(*attr);
    }
    elem
}
