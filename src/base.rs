//! Base One-Time Password (OTP) functionality.

use std::array;

use bon::Builder;
use constant_time_eq::constant_time_eq;

#[cfg(feature = "auth")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "auth")]
use thiserror::Error;

#[cfg(feature = "auth")]
use url::Url;

use crate::{algorithm::Algorithm, digits::Digits, secret::core::Secret};

#[cfg(feature = "auth")]
use crate::{algorithm, auth::query::Query, digits, secret};

/// Represents OTP base configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Base<'b> {
    /// The secret to use as the key.
    pub secret: Secret<'b>,
    /// The algorithm to use.
    #[builder(default)]
    #[cfg_attr(feature = "serde", serde(default))]
    pub algorithm: Algorithm,
    /// The number of digits to return.
    #[builder(default)]
    #[cfg_attr(feature = "serde", serde(default))]
    pub digits: Digits,
}

/// The mask used to extract relevant bits.
pub const MASK: u32 = 0x7FFF_FFFF;
/// The half byte to extract the offset.
pub const HALF_BYTE: u8 = 0xF;

impl Base<'_> {
    /// Generates codes based on the given input.
    ///
    /// # Panics
    ///
    /// Even though [`unwrap`] and indexing are used, the code will never panic,
    /// provided the HMAC implementation is correct.
    ///
    /// [`unwrap`]: Option::unwrap
    pub fn generate(&self, input: u64) -> u32 {
        let hmac = self
            .algorithm
            .hmac(self.secret.as_ref(), input.to_be_bytes());

        let offset = (hmac.last().unwrap() & HALF_BYTE) as usize;
        let bytes = array::from_fn(|index| hmac[offset + index]);

        let value = u32::from_be_bytes(bytes) & MASK;

        value % self.digits.power()
    }

    /// Calls [`generate`] and returns the string representation of the resulting code.
    ///
    /// The resulting string is padded with zeros if needed (see [`string`]).
    ///
    /// [`generate`]: Self::generate
    /// [`string`]: Digits::string
    pub fn generate_string(&self, input: u64) -> String {
        self.digits.string(self.generate(input))
    }

    /// Verifies that the given code matches the given input.
    pub fn verify(&self, input: u64, code: u32) -> bool {
        self.generate(input) == code
    }

    /// Verifies that the given string code matches the given input in constant time.
    ///
    /// This method exists to simplify verification.
    pub fn verify_string<S: AsRef<str>>(&self, input: u64, code: S) -> bool {
        constant_time_eq(
            self.generate_string(input).as_bytes(),
            code.as_ref().as_bytes(),
        )
    }
}

/// The `secret` literal.
#[cfg(feature = "auth")]
pub const SECRET: &str = "secret";

/// The `algorithm` literal.
#[cfg(feature = "auth")]
pub const ALGORITHM: &str = "algorithm";

/// The `digits` literal.
#[cfg(feature = "auth")]
pub const DIGITS: &str = "digits";

/// Represents errors returned when the secret is not found in the OTP URL.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to find secret")]
#[diagnostic(code(otp_std::base::secret), help("make sure the secret is present"))]
pub struct SecretNotFoundError;

/// Represents sources of errors that can occur when extracting base configurations
/// from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The secret was not found in the OTP URL.
    SecretNotFound(#[from] SecretNotFoundError),
    /// The secret was found, but could not be parsed.
    Secret(#[from] secret::core::Error),
    /// The algorithm could not be parsed.
    Algorithm(#[from] algorithm::Error),
    /// The number of digits could not be parsed.
    Digits(#[from] digits::ParseError),
}

/// Represents errors that can occur when extracting the base from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract base from OTP URL")]
#[diagnostic(
    code(otp_std::base::extract),
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
    pub fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`SecretNotFoundError`].
    pub fn secret_not_found(error: SecretNotFoundError) -> Self {
        Self::new(error.into())
    }

    /// Creates [`SecretNotFoundError`] and constructs [`Self`] from it.
    pub fn new_secret_not_found() -> Self {
        Self::secret_not_found(SecretNotFoundError)
    }

    /// Constructs [`Self`] from [`secret::core::Error`].
    pub fn secret(error: secret::core::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`algorithm::Error`].
    pub fn algorithm(error: algorithm::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`digits::ParseError`].
    pub fn digits(error: digits::ParseError) -> Self {
        Self::new(error.into())
    }
}

#[cfg(feature = "auth")]
impl Base<'_> {
    /// Applies the base configuration to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        let secret = self.secret.encode();

        let algorithm = self.algorithm.static_str();

        let digits = self.digits.to_string();

        url.query_pairs_mut()
            .append_pair(SECRET, &secret)
            .append_pair(ALGORITHM, algorithm)
            .append_pair(DIGITS, &digits);
    }

    /// Extracts [`Self`] from the given URL query.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if extraction fails.
    pub fn extract_from(query: &mut Query<'_>) -> Result<Self, Error> {
        let secret = query
            .remove(SECRET)
            .ok_or_else(Error::new_secret_not_found)?
            .parse()
            .map_err(Error::secret)?;

        let maybe_algorithm = query
            .remove(ALGORITHM)
            .map(|string| string.parse())
            .transpose()
            .map_err(Error::algorithm)?;

        let maybe_digits = query
            .remove(DIGITS)
            .map(|string| string.parse())
            .transpose()
            .map_err(Error::digits)?;

        let base = Self::builder()
            .secret(secret)
            .maybe_algorithm(maybe_algorithm)
            .maybe_digits(maybe_digits)
            .build();

        Ok(base)
    }
}
