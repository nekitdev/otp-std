//! One-Time Password (OTP) enums.
//!
//! The [`Otp`] enum contains [`Hotp`] and [`Totp`] as its variants.

#[cfg(feature = "auth")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "auth")]
use thiserror::Error;

use crate::{base::Base, hotp::Hotp, otp::type_of::Type, totp::Totp};

#[cfg(feature = "auth")]
use crate::{
    auth::{query::Query, url::Url},
    hotp, totp,
};

/// Represents either [`Hotp`] or [`Totp`] configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
pub enum Otp<'o> {
    /// HOTP configuration.
    Hotp(Hotp<'o>),
    /// TOTP configuration.
    Totp(Totp<'o>),
}

impl<'o> Otp<'o> {
    /// Returns the base configuration, regardless of the variant.
    pub const fn base(&self) -> &Base<'o> {
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
    pub const fn type_of(&self) -> Type {
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
    pub const fn new(source: ErrorSource) -> Self {
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
    /// Applies [`Self`] to the given [`Url`].
    pub fn query_for(&self, url: &mut Url) {
        match self {
            Self::Hotp(hotp) => hotp.query_for(url),
            Self::Totp(totp) => totp.query_for(url),
        }
    }

    /// Extracts [`Self`] from the given [`Query`].
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] when the OTP configuration can not be extracted.
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

impl<'h> From<Hotp<'h>> for Otp<'h> {
    fn from(hotp: Hotp<'h>) -> Self {
        Self::Hotp(hotp)
    }
}

impl<'t> From<Totp<'t>> for Otp<'t> {
    fn from(totp: Totp<'t>) -> Self {
        Self::Totp(totp)
    }
}

/// Represents owned [`Otp`].
pub type Owned = Otp<'static>;

impl Otp<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        match self {
            Self::Hotp(hotp) => Owned::Hotp(hotp.into_owned()),
            Self::Totp(totp) => Owned::Totp(totp.into_owned()),
        }
    }
}
