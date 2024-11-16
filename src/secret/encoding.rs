//! Secret encoding and decoding.

use base32::Alphabet;
use miette::Diagnostic;
use thiserror::Error;

/// Represents errors that can occur when secret decoding fails.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to decode `{secret}` secret")]
#[diagnostic(code(otp_std::secret::encoding), help("make sure the secret is valid"))]
pub struct Error {
    /// The encoded secret that could not be decoded.
    pub secret: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(secret: String) -> Self {
        Self { secret }
    }
}

/// The alphabet used for encoding and decoding OTP secrets.
pub const ALPHABET: Alphabet = Alphabet::Rfc4648 { padding: false };

/// Encodes the given secret.
pub fn encode<S: AsRef<[u8]>>(secret: S) -> String {
    base32::encode(ALPHABET, secret.as_ref())
}

/// Decodes the given secret.
///
/// # Errors
///
/// Returns [`struct@Error`] if the secret could not be decoded.
pub fn decode<S: AsRef<str>>(secret: S) -> Result<Vec<u8>, Error> {
    let secret = secret.as_ref();

    base32::decode(ALPHABET, secret).ok_or_else(|| Error::new(secret.to_owned()))
}
