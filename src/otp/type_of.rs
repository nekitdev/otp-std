//! One-Time Password (OTP) types.
//!
//! This module provides the [`Type`] enum which represents OTP types.

use std::{fmt, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::macros::errors;

#[cfg(feature = "auth")]
use crate::auth::url::Url;

/// Represents OTP types: HOTP or TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    /// HOTP type.
    Hotp,
    /// TOTP type.
    Totp,
}

#[cfg(feature = "serde")]
impl Serialize for Type {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.static_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Type {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = <&str>::deserialize(deserializer)?;

        string.parse().map_err(de::Error::custom)
    }
}

/// The `hotp` literal.
pub const HOTP: &str = "hotp";

/// The `totp` literal.
pub const TOTP: &str = "totp";

impl Type {
    /// Returns the static string representation of this type.
    pub const fn static_str(&self) -> &'static str {
        match self {
            Self::Hotp => HOTP,
            Self::Totp => TOTP,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.static_str().fmt(formatter)
    }
}

/// Represents errors that can occur when parsing [`Type`].
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` into type; expected either `{HOTP}` or `{TOTP}`")]
#[diagnostic(
    code(otp_std::otp::type_of::parse),
    help("see the report for more information")
)]
pub struct ParseError {
    /// The string that could not be parsed.
    pub string: String,
}

impl ParseError {
    /// Constructs [`Self`].
    pub const fn new(string: String) -> Self {
        Self { string }
    }
}

/// Represents errors that can occur when the type is not found in the OTP URL.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to find OTP type")]
#[diagnostic(
    code(otp_std::otp::type_of::not_found),
    help("see the report for more information")
)]
pub struct NotFoundError;

/// Represents sources of errors that can occur when extracting the type from the OTP URL.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The type was not found.
    NotFound(#[from] NotFoundError),
    /// The type was found, but could not be parsed.
    Parse(#[from] ParseError),
}

/// Represents errors that can occur when extracting the type from the OTP URL.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract type from OTP URL")]
#[diagnostic(
    code(otp_std::otp::type_of),
    help("see the report for more information")
)]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

#[cfg(feature = "auth")]
impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`NotFoundError`].
    pub fn not_found(error: NotFoundError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`NotFoundError`] and constructs [`Self`] from it.
    pub fn new_not_found() -> Self {
        Self::not_found(NotFoundError)
    }

    /// Constructs [`Self`] from [`ParseError`].
    pub fn parse(error: ParseError) -> Self {
        Self::new(error.into())
    }
}

#[cfg(feature = "auth")]
errors! {
    Type = Error,
    Hack = $,
    not_found_error => new_not_found(),
    parse_error => parse(error),
}

#[cfg(feature = "auth")]
impl Type {
    /// Extracts the type from the given URL.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the type can not be extracted from the given URL.
    pub fn extract_from(url: &Url) -> Result<Self, Error> {
        let host = url.host_str().ok_or_else(|| not_found_error!())?;

        host.parse().map_err(|error| parse_error!(error))
    }
}

errors! {
    Type = ParseError,
    Hack = $,
    error => new(string => to_owned),
}

impl FromStr for Type {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            HOTP => Ok(Self::Hotp),
            TOTP => Ok(Self::Totp),
            _ => Err(error!(string)),
        }
    }
}
