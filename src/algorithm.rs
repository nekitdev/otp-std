//! Hash-based Message Authentication Code (HMAC) functionality.

use std::{fmt, str::FromStr};

use hmac::{Hmac, Mac};

use miette::Diagnostic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use sha1::Sha1;

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512};

use thiserror::Error;

/// HMAC type using SHA-1.
pub type HmacSha1 = Hmac<Sha1>;

/// HMAC type using SHA-256.
#[cfg(feature = "sha2")]
pub type HmacSha256 = Hmac<Sha256>;

/// HMAC type using SHA-512.
#[cfg(feature = "sha2")]
pub type HmacSha512 = Hmac<Sha512>;

/// Represents errors that occur when unknown algorithms are encountered.
#[derive(Debug, Error, Diagnostic)]
#[error("unknown algorithm `{unknown}`")]
#[diagnostic(code(otp_std::algorithm), help("make sure the algorithm is supported"))]
pub struct Error {
    /// The unknown algorithm.
    pub unknown: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(unknown: String) -> Self {
        Self { unknown }
    }
}

/// Represents hash algorithms used in HMACs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "SCREAMING_SNAKE_CASE"))]
pub enum Algorithm {
    /// SHA-1 algorithm.
    #[default]
    Sha1,
    /// SHA-256 algorithm.
    #[cfg(feature = "sha2")]
    Sha256,
    /// SHA-512 algorithm.
    #[cfg(feature = "sha2")]
    Sha512,
}

/// The `SHA1` literal.
pub const SHA1: &str = "SHA1";

/// The `SHA256` literal.
#[cfg(feature = "sha2")]
pub const SHA256: &str = "SHA256";

/// The `SHA512` literal.
#[cfg(feature = "sha2")]
pub const SHA512: &str = "SHA512";

impl Algorithm {
    /// Returns the static string representation of [`Self`].
    pub const fn static_str(&self) -> &'static str {
        match self {
            Self::Sha1 => SHA1,
            #[cfg(feature = "sha2")]
            Self::Sha256 => SHA256,
            #[cfg(feature = "sha2")]
            Self::Sha512 => SHA512,
        }
    }

    /// Computes HMAC using the [`Self`] algorithm, the key provided, and the given data.
    pub fn hmac<K: AsRef<[u8]>, D: AsRef<[u8]>>(&self, key: K, data: D) -> Vec<u8> {
        match self {
            Self::Sha1 => hmac_sha1(key, data),
            #[cfg(feature = "sha2")]
            Self::Sha256 => hmac_sha256(key, data),
            #[cfg(feature = "sha2")]
            Self::Sha512 => hmac_sha512(key, data),
        }
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            SHA1 => Ok(Self::Sha1),
            #[cfg(feature = "sha2")]
            SHA256 => Ok(Self::Sha256),
            #[cfg(feature = "sha2")]
            SHA512 => Ok(Self::Sha512),
            _ => Err(Error::new(string.to_owned())),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.static_str().fmt(formatter)
    }
}

/// Computes the HMAC of the given data.
pub fn hmac<M: Mac, D: AsRef<[u8]>>(mut mac: M, data: D) -> Vec<u8> {
    mac.update(data.as_ref());

    mac.finalize().into_bytes().to_vec()
}

/// HMAC must accept any key length.
pub const HMAC_ANY_KEY_LENGTH: &str = "hmac must accept any key length";

/// Computes the HMAC using the SHA-1 algorithm.
///
/// # Panics
///
/// HMAC must accept any key length, which means that the function should not panic.
pub fn hmac_sha1<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(
        HmacSha1::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH),
        data,
    )
}

/// Computes the HMAC using the SHA-256 algorithm.
///
/// # Panics
///
/// HMAC must accept any key length, which means that the function should not panic.
#[cfg(feature = "sha2")]
pub fn hmac_sha256<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(
        HmacSha256::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH),
        data,
    )
}

/// Computes the HMAC using the SHA-512 algorithm.
///
/// # Panics
///
/// HMAC must accept any key length, which means that the function should not panic.
#[cfg(feature = "sha2")]
pub fn hmac_sha512<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(
        HmacSha512::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH),
        data,
    )
}
