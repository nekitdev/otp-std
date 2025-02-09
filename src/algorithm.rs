//! Hash-based Message Authentication Code (HMAC) functionality.

use std::{fmt, str::FromStr};

use hmac::{Hmac, Mac};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use sha1::Sha1;

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha512};

use thiserror::Error;

#[cfg(feature = "serde")]
use crate::macros::deserialize_str;

use crate::macros::errors;

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

impl Algorithm {
    /// The amount of algorithms available.
    #[cfg(not(feature = "sha2"))]
    pub const COUNT: usize = 1;

    /// The array of algorithms available.
    #[cfg(not(feature = "sha2"))]
    pub const ARRAY: [Self; Self::COUNT] = [Self::Sha1];

    /// The amount of algorithms available.
    #[cfg(feature = "sha2")]
    pub const COUNT: usize = 3;

    /// The array of algorithms available.
    #[cfg(feature = "sha2")]
    pub const ARRAY: [Self; Self::COUNT] = [Self::Sha1, Self::Sha256, Self::Sha512];
}

/// The `SHA1` literal.
pub const SHA1: &str = "SHA1";

/// The length of the SHA-1 hash.
pub const SHA1_LENGTH: usize = 20;

/// The length of the SHA-256 hash.
#[cfg(feature = "sha2")]
pub const SHA256_LENGTH: usize = 32;

/// The length of the SHA-512 hash.
#[cfg(feature = "sha2")]
pub const SHA512_LENGTH: usize = 64;

/// The `SHA256` literal.
#[cfg(feature = "sha2")]
pub const SHA256: &str = "SHA256";

/// The `SHA512` literal.
#[cfg(feature = "sha2")]
pub const SHA512: &str = "SHA512";

#[cfg(feature = "serde")]
impl Serialize for Algorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.static_str().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Algorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = deserialize_str!(deserializer)?;

        string.parse().map_err(de::Error::custom)
    }
}

impl Algorithm {
    /// Returns the static string representation of [`Self`].
    pub const fn static_str(self) -> &'static str {
        match self {
            Self::Sha1 => SHA1,
            #[cfg(feature = "sha2")]
            Self::Sha256 => SHA256,
            #[cfg(feature = "sha2")]
            Self::Sha512 => SHA512,
        }
    }

    /// Returns the recommended length of the key for [`Self`].
    pub const fn recommended_length(self) -> usize {
        match self {
            Self::Sha1 => SHA1_LENGTH,
            #[cfg(feature = "sha2")]
            Self::Sha256 => SHA256_LENGTH,
            #[cfg(feature = "sha2")]
            Self::Sha512 => SHA512_LENGTH,
        }
    }

    /// Computes HMAC using the [`Self`] algorithm, the key provided, and the given data.
    pub fn hmac<K: AsRef<[u8]>, D: AsRef<[u8]>>(self, key: K, data: D) -> Vec<u8> {
        match self {
            Self::Sha1 => hmac_sha1(key, data),
            #[cfg(feature = "sha2")]
            Self::Sha256 => hmac_sha256(key, data),
            #[cfg(feature = "sha2")]
            Self::Sha512 => hmac_sha512(key, data),
        }
    }
}

errors! {
    Type = Error,
    Hack = $,
    error => new(string => to_owned),
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
            _ => Err(error!(string)),
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

/// HMAC accepts any key length.
pub const HMAC_ANY_KEY_LENGTH: &str = "hmac accepts any key length";

/// Creates HMAC using the SHA-1 algorithm.
///
/// # Panics
///
/// HMAC accepts any key length, which means this function will not panic.
pub fn new_hmac_sha1<K: AsRef<[u8]>>(key: K) -> HmacSha1 {
    HmacSha1::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH)
}

/// Computes the HMAC using the SHA-1 algorithm.
pub fn hmac_sha1<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(new_hmac_sha1(key), data)
}

/// Creates HMAC using the SHA-256 algorithm.
///
/// # Panics
///
/// HMAC accepts any key length, which means this function will not panic.
#[cfg(feature = "sha2")]
pub fn new_hmac_sha256<K: AsRef<[u8]>>(key: K) -> HmacSha256 {
    HmacSha256::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH)
}

/// Computes the HMAC using the SHA-256 algorithm.
#[cfg(feature = "sha2")]
pub fn hmac_sha256<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(new_hmac_sha256(key), data)
}

/// Creates HMAC using the SHA-512 algorithm.
///
/// # Panics
///
/// HMAC accepts any key length, which means this function will not panic.
#[cfg(feature = "sha2")]
pub fn new_hmac_sha512<K: AsRef<[u8]>>(key: K) -> HmacSha512 {
    HmacSha512::new_from_slice(key.as_ref()).expect(HMAC_ANY_KEY_LENGTH)
}

/// Computes the HMAC using the SHA-512 algorithm.
#[cfg(feature = "sha2")]
pub fn hmac_sha512<K: AsRef<[u8]>, D: AsRef<[u8]>>(key: K, data: D) -> Vec<u8> {
    hmac(new_hmac_sha512(key), data)
}
