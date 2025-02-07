//! URL functionality.
//!
//! This module re-exports [`url::Url`] and provides the [`struct@Error`] type
//! that wraps [`url::ParseError`] to provide diagnostics.

use miette::Diagnostic;
use thiserror::Error;

pub use url::Url;
pub use urlencoding::{decode, encode};

use crate::{
    auth::{label::Label, scheme::SCHEME},
    otp::Type,
};

/// Wraps [`url::ParseError`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse OTP URL")]
#[diagnostic(code(otp_std::auth::url), help("make sure the OTP URL is valid"))]
pub struct Error(#[from] pub url::ParseError);

/// Parses the given string into [`Url`].
///
/// # Errors
///
/// Returns [`struct@Error`] when the string can not be parsed into URL.
pub fn parse<S: AsRef<str>>(string: S) -> Result<Url, Error> {
    Url::parse(string.as_ref()).map_err(Error)
}

/// The message indicating that the OTP base URL is always valid.
pub const BASE_ALWAYS_VALID: &str = "OTP base URL is always valid";

/// Returns the base OTP URL for the given type and label.
///
/// # Panics
///
/// This function can not panic because the base URL is always valid.
pub fn base(type_of: Type, label: &Label<'_>) -> Url {
    let string = format!("{SCHEME}://{type_of}/{label}");

    parse(string).expect(BASE_ALWAYS_VALID)
}
