//! Core functionality for authentication.

use bon::Builder;
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{
    auth::{
        self,
        label::{self, Label},
        query::Query,
        scheme,
        url::{self, Url},
    },
    macros::errors,
    otp::{
        self,
        core::Otp,
        type_of::{self, Type},
    },
};

/// The scheme of OTP URLs.
pub const SCHEME: &str = "otpauth";

/// Base OTP URL is always valid.
pub const BASE_URL_ALWAYS_VALID: &str = "OTP base URL is always valid";

/// Represents OTP authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Auth<'a> {
    /// The OTP configuration.
    #[builder(into)]
    pub otp: Otp<'a>,
    /// The authentication label.
    pub label: Label<'a>,
}

/// Represents sources of errors that can occur when parsing OTP URLs.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// URL could not be parsed.
    Url(#[from] url::Error),
    /// Unexpected scheme found.
    Scheme(#[from] scheme::Error),
    /// OTP type extraction failed.
    TypeOf(#[from] type_of::Error),
    /// Label could not be extracted.
    Label(#[from] label::Error),
    /// OTP extraction failed.
    Otp(#[from] otp::core::Error),
}

/// Represents errors that can occur when parsing OTP URLs.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract auth from `{string}`")]
#[diagnostic(code(otp_std::auth::core), help("see the report for more information"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
    /// The string that could not be parsed.
    pub string: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ErrorSource, string: String) -> Self {
        Self { source, string }
    }

    /// Constructs [`Self`] from [`url::Error`].
    pub fn parse(error: url::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`scheme::Error`].
    pub fn scheme(error: scheme::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`type_of::Error`].
    pub fn type_of(error: type_of::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`label::Error`].
    pub fn label(error: label::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`otp::core::Error`].
    pub fn otp(error: otp::core::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }
}

impl Auth<'_> {
    /// Returns the OTP configuration reference.
    pub const fn otp(&self) -> &Otp<'_> {
        &self.otp
    }

    /// Returns the label reference.
    pub const fn label(&self) -> &Label<'_> {
        &self.label
    }
}

/// Represents `(otp, label)` parts of the authentication.
pub type Parts<'p> = (Otp<'p>, Label<'p>);

/// Represents owned [`Parts`].
pub type OwnedParts = Parts<'static>;

impl<'a> Auth<'a> {
    /// Constructs [`Self`] from parts.
    pub fn from_parts(parts: Parts<'a>) -> Self {
        let (otp, label) = parts;

        Self::builder().otp(otp).label(label).build()
    }

    /// Consumes [`Self`], returning the contained parts.
    pub fn into_parts(self) -> Parts<'a> {
        (self.otp, self.label)
    }
}

impl<'p> From<Parts<'p>> for Auth<'p> {
    fn from(parts: Parts<'p>) -> Self {
        Self::from_parts(parts)
    }
}

impl<'a> From<Auth<'a>> for Parts<'a> {
    fn from(auth: Auth<'a>) -> Self {
        auth.into_parts()
    }
}

errors! {
    Type = Error,
    Hack = $,
    parse_error => parse(error, string => to_owned),
    scheme_error => scheme(error, string => to_owned),
    type_of_error => type_of(error, string => to_owned),
    label_error => label(error, string => to_owned),
    otp_error => otp(error, string => to_owned),
}

impl Auth<'_> {
    /// Constructs the OTP URL base.
    ///
    /// # Panics
    ///
    /// The base URL is always valid, so this method should never panic.
    pub fn base_url(&self) -> Url {
        url::base(self.otp().type_of(), self.label())
    }

    /// Builds the OTP URL, applying query parameters to the base URL created.
    pub fn build_url(&self) -> Url {
        let mut url = self.base_url();

        self.query_for(&mut url);

        url
    }

    /// Applies the OTP configuration and the issuer to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        self.otp().query_for(url);
        self.label().query_for(url);
    }

    /// Parses the OTP URL from the given string.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if anything goes wrong.
    pub fn parse_url<S: AsRef<str>>(string: S) -> Result<Self, Error> {
        fn parse_url_inner(string: &str) -> Result<OwnedParts, Error> {
            let url = auth::url::parse(string).map_err(|error| parse_error!(error, string))?;

            auth::scheme::check_url(&url).map_err(|error| scheme_error!(error, string))?;

            let type_of =
                Type::extract_from(&url).map_err(|error| type_of_error!(error, string))?;

            let mut query: Query<'_> = url.query_pairs().collect();

            let label = Label::extract_from(&mut query, &url)
                .map_err(|error| label_error!(error, string))?;

            let otp = Otp::extract_from(&mut query, type_of)
                .map_err(|error| otp_error!(error, string))?;

            Ok((otp, label))
        }

        parse_url_inner(string.as_ref()).map(Self::from_parts)
    }
}

/// Represents owned [`Auth`].
pub type Owned = Auth<'static>;

impl Auth<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        Owned::builder()
            .otp(self.otp.into_owned())
            .label(self.label.into_owned())
            .build()
    }
}
