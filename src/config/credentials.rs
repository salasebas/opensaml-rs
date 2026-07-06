use core::fmt;

/// PEM-encoded private key material.
///
/// `Debug` is intentionally redacted so key material is not dumped through
/// public config structs.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyPem(String);

impl PrivateKeyPem {
    /// Wrap PEM-encoded private key material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text.
    ///
    /// The value is secret-bearing key material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyPem(<redacted>)")
    }
}

/// PEM-encoded X.509 certificate material.
///
/// `Debug` avoids printing the certificate body by default because certificate
/// fields often travel beside private key configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificatePem(String);

impl CertificatePem {
    /// Wrap PEM-encoded certificate material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text for internal compatibility mapping.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CertificatePem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertificatePem(<redacted>)")
    }
}

/// Passphrase used to decrypt private key material.
///
/// `Debug` is intentionally redacted so passphrases are not exposed through
/// logs or failing assertions.
#[derive(Clone, PartialEq, Eq)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wrap passphrase text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the passphrase text.
    ///
    /// The value is secret-bearing credential material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}
/// Secret-bearing and certificate material for local SAML operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// Signing private key.
    pub signing_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::signing_key`].
    pub signing_key_passphrase: Option<Passphrase>,
    /// Signing certificate.
    pub signing_certificate: Option<CertificatePem>,
    /// Encryption certificate advertised for peers.
    pub encryption_certificate: Option<CertificatePem>,
    /// Decryption private key for encrypted assertions.
    pub decryption_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::decryption_key`].
    pub decryption_key_passphrase: Option<Passphrase>,
}
