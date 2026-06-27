//! SAML HTTP binding helpers: POST form, Redirect query, DEFLATE, base64,
//! and XML/HTML escaping.

mod deflate;
mod encoding;
mod escape;
mod post_form;
mod redirect;

pub use deflate::{
    deflate_raw_decode, deflate_raw_decode_with_limit, deflate_raw_encode,
    MAX_DEFLATE_RAW_DECODE_BYTES,
};
pub use encoding::{base64_decode, base64_encode};
pub use escape::{html_escape, xml_escape};
pub use post_form::saml_post_binding_form;
pub use redirect::{
    append_signature, build_redirect_octet, build_redirect_url, redirect_binding_query,
};
