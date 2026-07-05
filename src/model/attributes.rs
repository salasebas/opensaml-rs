/// A single SAML attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValue(String);

impl AttributeValue {
    /// Wrap an attribute value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the attribute value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SAML attribute with one or more values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    name_format: Option<String>,
    values: Vec<AttributeValue>,
}

impl Attribute {
    /// Create a SAML attribute.
    pub fn new(
        name: impl Into<String>,
        name_format: Option<String>,
        values: Vec<AttributeValue>,
    ) -> Self {
        Self {
            name: name.into(),
            name_format,
            values,
        }
    }

    /// Attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Attribute name format, when extracted.
    pub fn name_format(&self) -> Option<&str> {
        self.name_format.as_deref()
    }

    /// Attribute values.
    pub fn values(&self) -> &[AttributeValue] {
        &self.values
    }
}

/// Collection of SAML attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// Create an attribute collection.
    pub fn new(values: Vec<Attribute>) -> Self {
        Self(values)
    }

    /// Borrow the attributes as a slice.
    pub fn as_slice(&self) -> &[Attribute] {
        &self.0
    }

    /// Find an attribute by name.
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.0.iter().find(|attribute| attribute.name() == name)
    }
}

impl IntoIterator for Attributes {
    type Item = Attribute;
    type IntoIter = std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
