//! Authentication parts.

use std::{borrow::Cow, fmt, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::{
    auth::{url, utf8},
    macros::{errors, quick_error},
};

/// The separator used to join parts.
pub const SEPARATOR: &str = ":";

/// Represents authentication parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Part<'p> {
    string: Cow<'p, str>,
}

#[cfg(feature = "serde")]
impl Serialize for Part<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Part<'_> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = Cow::deserialize(deserializer)?;

        Self::new(string).map_err(de::Error::custom)
    }
}

/// Represents errors returned when the part is empty.
#[derive(Debug, Error, Diagnostic)]
#[error("the part is empty")]
#[diagnostic(
    code(otp_std::auth::part::empty),
    help("make sure the part is not empty")
)]
pub struct EmptyError;

/// Represents errors returned when parts contain the [`SEPARATOR`].
#[derive(Debug, Error, Diagnostic)]
#[error("unexpected `{SEPARATOR}` in `{string}`")]
#[diagnostic(
    code(otp_std::auth::part::separator),
    help("make sure the part does not contain `{SEPARATOR}`")
)]
pub struct SeparatorError {
    /// The string that contains the separator.
    pub string: String,
}

impl SeparatorError {
    /// Constructs [`Self`].
    pub const fn new(string: String) -> Self {
        Self { string }
    }
}

/// Represents sources of errors that can occur when parsing parts.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The part is empty.
    Empty(#[from] EmptyError),
    /// The part contains the separator.
    Separator(#[from] SeparatorError),
}

/// Represents errors that can occur when parsing parts.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse part")]
#[diagnostic(code(otp_std::auth::part), help("see the report for more information"))]
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

    /// Constructs [`Self`] from [`EmptyError`].
    pub fn empty(error: EmptyError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`SeparatorError`].
    pub fn separator(error: SeparatorError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`EmptyError`] and constructs [`Self`] from it.
    pub fn new_empty() -> Self {
        Self::empty(EmptyError)
    }

    /// Constructs [`SeparatorError`] and constructs [`Self`] from it.
    pub fn new_separator(string: String) -> Self {
        Self::separator(SeparatorError::new(string))
    }
}

impl AsRef<str> for Part<'_> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Part<'_> {
    /// Returns the borrowed string.
    pub fn as_str(&self) -> &str {
        self.string.as_ref()
    }
}

impl fmt::Display for Part<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

impl FromStr for Part<'_> {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::check(string)?;

        Ok(unsafe { Self::owned_unchecked(string.to_owned()) })
    }
}

errors! {
    Type = Error,
    Hack = $,
    empty_error => new_empty(),
    separator_error => new_separator(string => to_owned),
}

impl<'p> Part<'p> {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given string is empty or contains the [`SEPARATOR`].
    pub fn new(string: Cow<'p, str>) -> Result<Self, Error> {
        Self::check(string.as_ref())?;

        Ok(unsafe { Self::new_unchecked(string) })
    }

    /// Checks whether the given string is valid for constructing [`Self`].
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given string is empty or contains the [`SEPARATOR`].
    pub fn check<S: AsRef<str>>(string: S) -> Result<(), Error> {
        fn check_inner(string: &str) -> Result<(), Error> {
            quick_error!(string.is_empty() => empty_error!());

            quick_error!(string.contains(SEPARATOR) => separator_error!(string));

            Ok(())
        }

        check_inner(string.as_ref())
    }

    /// Constructs [`Self`] without checking the given string.
    ///
    /// # Safety
    ///
    /// The given string must be non-empty and must not contain the [`SEPARATOR`].
    pub const unsafe fn new_unchecked(string: Cow<'p, str>) -> Self {
        Self { string }
    }

    /// Constructs [`Self`] from owned data, if possible.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given string is empty or contains the [`SEPARATOR`].
    pub fn owned(string: String) -> Result<Self, Error> {
        Self::new(Cow::Owned(string))
    }

    /// Constructs [`Self`] from owned data without checking the given string.
    ///
    /// # Safety
    ///
    /// The given string must be non-empty and must not contain the [`SEPARATOR`].
    pub const unsafe fn owned_unchecked(string: String) -> Self {
        Self::new_unchecked(Cow::Owned(string))
    }

    /// Constructs [`Self`] from borrowed data, if possible.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given string is empty or contains the [`SEPARATOR`].
    pub fn borrowed(string: &'p str) -> Result<Self, Error> {
        Self::new(Cow::Borrowed(string))
    }

    /// Constructs [`Self`] from borrowed data without checking the given string.
    ///
    /// # Safety
    ///
    /// The given string must be non-empty and must not contain the [`SEPARATOR`].
    pub const unsafe fn borrowed_unchecked(string: &'p str) -> Self {
        Self::new_unchecked(Cow::Borrowed(string))
    }

    /// Consumes [`Self`] and returns the contained string.
    pub fn get(self) -> Cow<'p, str> {
        self.string
    }
}

/// Represents sources of errors that can occur when decoding parts.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum DecodeErrorSource {
    /// The part contains invalid UTF-8.
    Utf8(#[from] utf8::Error),
    /// The part is empty or contains the separator.
    Part(#[from] Error),
}

/// Represents errors that can occur when decoding parts.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to decode part")]
#[diagnostic(
    code(otp_std::auth::part::decode),
    help("see the report for more information")
)]
pub struct DecodeError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: DecodeErrorSource,
}

impl DecodeError {
    /// Constructs [`Self`].
    pub const fn new(source: DecodeErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`utf8::Error`].
    pub fn utf8(error: utf8::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`struct@Error`].
    pub fn part(error: Error) -> Self {
        Self::new(error.into())
    }
}

impl Part<'_> {
    /// Decodes the given string.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the given string could not be decoded.
    pub fn decode<S: AsRef<str>>(string: S) -> Result<Self, DecodeError> {
        let decoded = url::decode(string.as_ref())
            .map_err(utf8::wrap)
            .map_err(DecodeError::utf8)?;

        Self::owned(decoded.into_owned()).map_err(DecodeError::part)
    }
}

impl Part<'_> {
    /// Encodes the contained string.
    pub fn encode(&self) -> Cow<'_, str> {
        url::encode(self.as_str())
    }
}

/// Represents owned [`Part`].
pub type Owned = Part<'static>;

impl Part<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        // SAFETY: the contained string is valid
        unsafe { Owned::owned_unchecked(self.string.into_owned()) }
    }
}
