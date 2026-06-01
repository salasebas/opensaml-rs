//! XML parsing and field extraction (samlify `extractor.ts` port) over quick-xml.

pub mod dom;
pub mod extract;
pub mod fields;

pub use extract::{extract, ExtractorField, LocalPath};
