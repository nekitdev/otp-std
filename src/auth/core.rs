//! Core functionality for authentication.

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;
use url::Url;

use crate::{
    auth::{
        label::{self, Label, ISSUER},
        part::{self, Part},
        query::Query,
    },
    hotp::Hotp,
    otp::{self, Otp, ParseTypeError},
    totp::Totp,
};

/// The scheme of OTP URLs.
pub const SCHEME: &str = "otpauth";

/// Base OTP URL is always valid.
pub const BASE_URL_ALWAYS_VALID: &str = "OTP base URL is always valid";

/// Represents OTP authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Auth<'a> {
    /// The OTP configuration.
    pub otp: Otp<'a>,
    /// The authentication label.
    pub label: Label<'a>,
}

/// Wraps [`url::ParseError`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse OTP URL")]
#[diagnostic(
    code(otp_std::auth::core::parse),
    help("make sure the OTP URL is valid")
)]
pub struct ParseError(#[from] pub url::ParseError);

/// Represents errors that occur when unexpected schemes are encountered.
///
/// The only scheme valid for OTP URLs is [`SCHEME`].
#[derive(Debug, Error, Diagnostic)]
#[error("unexpected scheme `{scheme}`; expected `{SCHEME}`")]
#[diagnostic(
    code(otp_std::auth::core::scheme),
    help("make sure the scheme is correct")
)]
pub struct SchemeError {
    /// The unexpected scheme.
    pub scheme: String,
}

impl SchemeError {
    /// Constructs [`Self`].
    pub fn new(scheme: String) -> Self {
        Self { scheme }
    }
}

/// Represents errors that occur when the OTP type is not found.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to find the type")]
#[diagnostic(
    code(otp_std::auth::core::type_not_found),
    help("make sure the type is present")
)]
pub struct TypeNotFoundError;

/// Represent errors that occur when the issuer mismatch happens.
#[derive(Debug, Error, Diagnostic)]
#[error("issuer mismatch")]
#[diagnostic(
    code(otp_std::auth::core::mismatch),
    help("make sure the issuer is correct")
)]
pub struct MismatchError;

/// Represents sources of errors that can occur when parsing OTP URLs.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// URL could not be parsed.
    Parse(#[from] ParseError),
    /// Unexpected scheme found.
    Scheme(#[from] SchemeError),
    /// OTP type was not found.
    TypeNotFound(#[from] TypeNotFoundError),
    /// OTP type was found, but could not be parsed.
    ParseType(#[from] ParseTypeError),
    /// Label could not be decoded.
    Label(#[from] label::DecodeError),
    /// Issuer could not be decoded.
    Issuer(#[from] part::DecodeError),
    /// Issuer mismatch.
    Mismatch(#[from] MismatchError),
    /// OTP extraction failed.
    Otp(#[from] otp::Error),
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
    pub fn new(source: ErrorSource, string: String) -> Self {
        Self { source, string }
    }

    /// Constructs [`Self`] from [`ParseError`].
    pub fn parse(error: ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`url::ParseError`].
    pub fn new_parse(error: url::ParseError, string: String) -> Self {
        Self::parse(ParseError(error), string)
    }

    /// Constructs [`Self`] from [`SchemeError`].
    pub fn scheme(error: SchemeError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`SchemeError`] and constructs [`Self`] from it.
    pub fn new_scheme(scheme: String, string: String) -> Self {
        Self::scheme(SchemeError::new(scheme), string)
    }

    /// Constructs [`Self`] from [`TypeNotFoundError`].
    pub fn type_not_found(error: TypeNotFoundError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`TypeNotFoundError`] and constructs [`Self`] from it.
    pub fn new_type_not_found(string: String) -> Self {
        Self::type_not_found(TypeNotFoundError, string)
    }

    /// Constructs [`Self`] from [`ParseTypeError`].
    pub fn parse_type(error: ParseTypeError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`label::DecodeError`].
    pub fn label(error: label::DecodeError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`part::DecodeError`].
    pub fn issuer(error: part::DecodeError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`MismatchError`].
    pub fn mismatch(error: MismatchError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`MismatchError`] and constructs [`Self`] from it.
    pub fn new_mismatch(string: String) -> Self {
        Self::mismatch(MismatchError, string)
    }

    /// Constructs [`Self`] from [`otp::Error`].
    pub fn otp(error: otp::Error, string: String) -> Self {
        Self::new(error.into(), string)
    }
}

/// The `/` literal.
pub const SLASH: &str = "/";

impl<'a> Auth<'a> {
    /// Constructs [`Self`] from the OTP configuration and the label provided.
    pub fn new(otp: Otp<'a>, label: Label<'a>) -> Self {
        Self { otp, label }
    }

    /// Constructs [`Self`] from the HOTP configuration and the label provided.
    pub fn hotp(hotp: Hotp<'a>, label: Label<'a>) -> Self {
        Self::new(Otp::Hotp(hotp), label)
    }

    /// Constructs [`Self`] from the TOTP configuration and the label provided.
    pub fn totp(totp: Totp<'a>, label: Label<'a>) -> Self {
        Self::new(Otp::Totp(totp), label)
    }

    /// Constructs the OTP URL base.
    ///
    /// # Panics
    ///
    /// The base URL is always valid, so this method should never panic.
    pub fn base_url(&self) -> Url {
        let type_of = self.otp.type_of();
        let label = self.label.encode();

        let string = format!("{SCHEME}://{type_of}/{label}");

        Url::parse(&string).expect(BASE_URL_ALWAYS_VALID)
    }

    /// Builds the OTP URL, applying query parameters to the base URL created.
    pub fn build_url(&self) -> Url {
        let mut url = self.base_url();

        self.query_for(&mut url);

        url
    }

    /// Applies the OTP configuration and the issuer to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        self.otp.query_for(url);
        self.label.query_for(url);
    }

    /// Parses the OTP URL from the given string.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if anything goes wrong.
    pub fn parse_url<S: AsRef<str>>(string: S) -> Result<Self, Error> {
        let string = string.as_ref();

        let url = Url::parse(string).map_err(|error| Error::new_parse(error, string.to_owned()))?;

        let scheme = url.scheme();

        if scheme != SCHEME {
            return Err(Error::new_scheme(scheme.to_owned(), string.to_owned()));
        }

        let type_of = url
            .host_str()
            .ok_or_else(|| Error::new_type_not_found(string.to_owned()))?
            .parse()
            .map_err(|error| Error::parse_type(error, string.to_owned()))?;

        let path = url.path().trim_start_matches(SLASH);

        let decoded_label =
            Label::decode(path).map_err(|error| Error::label(error, string.to_owned()))?;

        // we will need to reconstruct the label
        let user = decoded_label.user;

        let mut query: Query<'_> = url.query_pairs().collect();

        let query_issuer = query
            .remove(ISSUER)
            .map(Part::decode)
            .transpose()
            .map_err(|error| Error::issuer(error, string.to_owned()))?;

        let issuer = match (decoded_label.issuer, query_issuer) {
            (Some(value), Some(other)) if value != other => {
                return Err(Error::new_mismatch(string.to_owned()));
            }
            (label_issuer, query_issuer) => label_issuer.or(query_issuer),
        };

        let label = Label::builder().maybe_issuer(issuer).user(user).build();

        let otp = Otp::extract_from(&mut query, type_of)
            .map_err(|error| Error::otp(error, string.to_owned()))?;

        let auth = Self::new(otp, label);

        Ok(auth)
    }
}
