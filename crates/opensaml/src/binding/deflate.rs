//! Raw DEFLATE (RFC 1951) used by the SAML HTTP-Redirect binding.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::error::OpenSamlError;

/// Raw-DEFLATE compress `input` (no zlib/gzip header), as required by the
/// HTTP-Redirect binding.
pub fn deflate_raw_encode(input: &[u8]) -> Result<Vec<u8>, OpenSamlError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

/// Inflate raw-DEFLATE `input` produced by [`deflate_raw_encode`].
pub fn deflate_raw_decode(input: &[u8]) -> Result<Vec<u8>, OpenSamlError> {
    let mut decoder = DeflateDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}
