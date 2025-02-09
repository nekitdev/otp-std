//! Authentication scheme.

use miette::Diagnostic;
use thiserror::Error;

use crate::{
    auth::url::Url,
    macros::{errors, quick_check},
};

/// The scheme used in OTP URLs.
pub const SCHEME: &str = "otpauth";

/// Represents errors that occur when unexpected schemes are encountered.
///
/// The only scheme valid for OTP URLs is [`SCHEME`].
#[derive(Debug, Error, Diagnostic)]
#[error("unexpected scheme `{scheme}`; expected `{SCHEME}`")]
#[diagnostic(code(otp_std::auth::scheme), help("make sure the scheme is correct"))]
pub struct Error {
    /// The unexpected scheme.
    pub scheme: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(scheme: String) -> Self {
        Self { scheme }
    }
}

errors! {
    Type = Error,
    Hack = $,
    error => new(scheme => to_owned),
}

/// Checks whether the given scheme matches [`SCHEME`].
///
/// # Errors
///
/// Returns [`struct@Error`] when the scheme does not match [`SCHEME`].
pub fn check<S: AsRef<str>>(scheme: S) -> Result<(), Error> {
    fn check_inner(scheme: &str) -> Result<(), Error> {
        quick_check!(scheme != SCHEME => error!(scheme));

        Ok(())
    }

    check_inner(scheme.as_ref())
}

/// Checks whether the given URL has the scheme matching [`SCHEME`].
///
/// # Errors
///
/// Returns [`struct@Error`] when the URL scheme does not match [`SCHEME`].
pub fn check_url(url: &Url) -> Result<(), Error> {
    check(url.scheme())
}
