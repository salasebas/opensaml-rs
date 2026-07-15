//! XML parsing and field extraction over quick-xml.

pub mod dom;
pub mod extract;
pub mod fields;
mod profile;
pub(crate) mod write;

pub use dom::XmlLimits;
pub use extract::{extract, extract_with_limits, ExtractorField, LocalPath};
pub(crate) use profile::validate_protocol_profile;
