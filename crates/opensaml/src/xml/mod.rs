//! XML parsing and field extraction (samlify `extractor.ts` port) over quick-xml.

pub mod dom;
pub mod extract;
pub mod fields;
pub(crate) mod write;

pub use dom::XmlLimits;
pub use extract::{extract, extract_with_limits, ExtractorField, LocalPath};
