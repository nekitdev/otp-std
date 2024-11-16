//! One-Time Password (OTP) configuration enums.
//!
//! The [`Otp`] enum contains [`Hotp`] and [`Totp`] as its variants.

use std::{fmt, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

#[cfg(feature = "auth")]
use url::Url;

use crate::{base::Base, hotp::Hotp, totp::Totp};

#[cfg(feature = "auth")]
use crate::{auth::query::Query, hotp, totp};

/// Represents either [`Hotp`] or [`Totp`] configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Otp<'o> {
    /// HOTP configuration.
    Hotp(Hotp<'o>),
    /// TOTP configuration.
    Totp(Totp<'o>),
}

impl<'o> Otp<'o> {
    /// Returns the base configuration, regardless of the variant.
    pub fn base(&self) -> &Base<'o> {
        match self {
            Self::Hotp(hotp) => hotp.base(),
            Self::Totp(totp) => totp.base(),
        }
    }

    /// Returns the mutable base configuration, regardless of the variant.
    pub fn base_mut(&mut self) -> &mut Base<'o> {
        match self {
            Self::Hotp(hotp) => hotp.base_mut(),
            Self::Totp(totp) => totp.base_mut(),
        }
    }

    /// Consumes [`Self`], returning the base configuration, regardless of the variant.
    pub fn into_base(self) -> Base<'o> {
        match self {
            Self::Hotp(hotp) => hotp.into_base(),
            Self::Totp(totp) => totp.into_base(),
        }
    }
}

impl Otp<'_> {
    /// Returns the [`Type`] of this OTP configuration.
    pub fn type_of(&self) -> Type {
        match self {
            Self::Hotp(_) => Type::Hotp,
            Self::Totp(_) => Type::Totp,
        }
    }
}

/// Represents sources of errors that can occur when extracting OTP configurations from URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The HOTP configuration could not be extracted.
    Hotp(#[from] hotp::Error),
    /// The TOTP configuration could not be extracted.
    Totp(#[from] totp::Error),
}

/// Represents errors that can occur when extracting OTP configurations from URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract OTP from URL")]
#[diagnostic(code(otp_std::otp), help("see the report for more information"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

#[cfg(feature = "auth")]
impl Error {
    /// Constructs [`Self`].
    pub fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`hotp::Error`].
    pub fn hotp(error: hotp::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`totp::Error`].
    pub fn totp(error: totp::Error) -> Self {
        Self::new(error.into())
    }
}

#[cfg(feature = "auth")]
impl Otp<'_> {
    /// Applies the OTP configuration to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        match self {
            Self::Hotp(hotp) => hotp.query_for(url),
            Self::Totp(totp) => totp.query_for(url),
        }
    }

    /// Extracts the OTP configuration from the given URL of the given type.
    pub fn extract_from(query: &mut Query<'_>, type_of: Type) -> Result<Self, Error> {
        match type_of {
            Type::Hotp => Hotp::extract_from(query)
                .map(Self::Hotp)
                .map_err(Error::hotp),
            Type::Totp => Totp::extract_from(query)
                .map(Self::Totp)
                .map_err(Error::totp),
        }
    }
}

/// Represents types of OTPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Type {
    /// HOTP type.
    Hotp,
    /// TOTP type.
    Totp,
}

/// The `hotp` literal.
pub const HOTP: &str = "hotp";

/// The `totp` literal.
pub const TOTP: &str = "totp";

impl Type {
    /// Returns the static string representation of this type.
    pub fn static_str(&self) -> &'static str {
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
    code(otp_std::otp::parse_type),
    help("see the report for more information")
)]
pub struct ParseTypeError {
    /// The string that could not be parsed.
    pub string: String,
}

impl ParseTypeError {
    /// Constructs [`Self`].
    pub fn new(string: String) -> Self {
        Self { string }
    }
}

impl FromStr for Type {
    type Err = ParseTypeError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            HOTP => Ok(Self::Hotp),
            TOTP => Ok(Self::Totp),
            _ => Err(Self::Err::new(string.to_owned())),
        }
    }
}
