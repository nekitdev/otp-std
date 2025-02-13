//! Core types and functions for working with secrets.

use std::{
    borrow::Cow,
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use constant_time_eq::constant_time_eq;
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::secret::{
    encoding,
    length::{self, Length},
};

#[cfg(feature = "generate-secret")]
use crate::secret::generate::generate;

/// Represents secrets.
#[derive(Debug, Clone)]
pub struct Secret<'s> {
    value: Cow<'s, [u8]>,
}

#[cfg(feature = "serde")]
impl Serialize for Secret<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.encode().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Secret<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = <&str>::deserialize(deserializer)?;

        Self::decode(string).map_err(de::Error::custom)
    }
}

impl fmt::Display for Secret<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.encode().fmt(formatter)
    }
}

impl PartialEq for Secret<'_> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

impl Eq for Secret<'_> {}

impl Hash for Secret<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl AsRef<[u8]> for Secret<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Represents sources of errors that can occur when decoding secrets.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// Secret has an unsafe length.
    Length(#[from] length::Error),
    /// Secret could not be decoded.
    Encoding(#[from] encoding::Error),
}

/// Represents errors that can occur when decoding secrets.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to decode secret")]
#[diagnostic(code(otp_std::secret), help("make sure the secret is valid"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`length::Error`].
    pub fn length(error: length::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`encoding::Error`].
    pub fn encoding(error: encoding::Error) -> Self {
        Self::new(error.into())
    }
}

impl<'s> Secret<'s> {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// Returns [`length::Error`] if the secret has an unsafe length.
    pub fn new(value: Cow<'s, [u8]>) -> Result<Self, length::Error> {
        Length::check(value.len())?;

        // SAFETY: the value has valid length for `Self`
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Constructs [`Self`] without checking the secret length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the secret length is safe.
    pub const unsafe fn new_unchecked(value: Cow<'s, [u8]>) -> Self {
        Self { value }
    }

    /// Constructs [`Self`] from borrowed data, if possible.
    ///
    /// # Errors
    ///
    /// Returns [`length::Error`] if the secret has an unsafe length.
    pub fn borrowed(value: &'s [u8]) -> Result<Self, length::Error> {
        Self::new(Cow::Borrowed(value))
    }

    /// Constructs [`Self`] from borrowed data without checking the secret length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the secret length is safe.
    pub const unsafe fn borrowed_unchecked(value: &'s [u8]) -> Self {
        Self::new_unchecked(Cow::Borrowed(value))
    }

    /// Constructs [`Self`] from owned data, if possible.
    ///
    /// # Errors
    ///
    /// Returns [`length::Error`] if the secret has an unsafe length.
    pub fn owned(value: Vec<u8>) -> Result<Self, length::Error> {
        Self::new(Cow::Owned(value))
    }

    /// Constructs [`Self`] from owned data without checking the secret length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the secret length is safe.
    pub const unsafe fn owned_unchecked(value: Vec<u8>) -> Self {
        Self::new_unchecked(Cow::Owned(value))
    }

    /// Consumes [`Self`] and returns the contained secret value.
    pub fn get(self) -> Cow<'s, [u8]> {
        self.value
    }
}

impl Secret<'_> {
    /// Returns the secret value as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_ref()
    }

    /// Decodes [`Self`] from the given string.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the secret could not be decoded.
    /// This can happen if the string is invalid or the resulting length is unsafe.
    pub fn decode<S: AsRef<str>>(string: S) -> Result<Self, Error> {
        let owned = encoding::decode(string).map_err(Error::encoding)?;

        let secret = Self::owned(owned).map_err(Error::length)?;

        Ok(secret)
    }

    /// Encodes [`Self`] into [`String`].
    pub fn encode(&self) -> String {
        encoding::encode(self.as_bytes())
    }
}

impl FromStr for Secret<'_> {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::decode(string)
    }
}

#[cfg(feature = "generate-secret")]
impl Secret<'_> {
    /// Generates secrets of the given length.
    pub fn generate(length: Length) -> Self {
        unsafe { Self::owned_unchecked(generate(length)) }
    }

    /// Generates secrets of default length.
    pub fn generate_default() -> Self {
        Self::generate(Length::default())
    }
}

#[cfg(feature = "generate-secret")]
impl Default for Secret<'_> {
    fn default() -> Self {
        Self::generate_default()
    }
}

/// Represents owned [`Secret`].
pub type Owned = Secret<'static>;

impl Secret<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        // SAFETY: the contained secret is valid (by construction)
        unsafe { Owned::owned_unchecked(self.get().into_owned()) }
    }
}
