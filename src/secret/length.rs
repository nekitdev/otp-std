//! Secret lengths.

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

#[cfg(not(feature = "unsafe-length"))]
use crate::macros::{errors, quick_check};

use crate::{
    algorithm::Algorithm,
    macros::{const_result_ok, const_try},
};

/// The default (and recommended) secret length.
pub const DEFAULT: usize = 20;

/// The minimum allowed secret length.
#[cfg(not(feature = "unsafe-length"))]
pub const MIN: usize = 16;

/// Represents errors returned when unsafe lengths are used.
#[cfg(not(feature = "unsafe-length"))]
#[derive(Debug, Error, Diagnostic)]
#[error("expected length of at least `{MIN}`, got `{length}`")]
#[diagnostic(
    code(otp_std::secret::length),
    help("make sure the secret length is at least `{MIN}`")
)]
pub struct Error {
    /// The unsafe length.
    pub length: usize,
}

#[cfg(not(feature = "unsafe-length"))]
impl Error {
    /// Constructs [`Self`].
    pub const fn new(length: usize) -> Self {
        Self { length }
    }
}

/// Represents the absence of errors returned when the `unsafe-length` feature is enabled.
#[cfg(feature = "unsafe-length")]
#[derive(Debug, Error, Diagnostic)]
pub enum Error {}

/// Represents OTP secret lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Length {
    value: usize,
}

#[cfg(feature = "serde")]
impl Serialize for Length {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Length {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = usize::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

impl TryFrom<usize> for Length {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Length> for usize {
    fn from(length: Length) -> Self {
        length.get()
    }
}

impl Default for Length {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(not(feature = "unsafe-length"))]
errors! {
    Type = Error,
    Hack = $,
    error => new(length),
}

impl Length {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// See [`check`] for more information.
    ///
    /// [`check`]: Self::check
    pub const fn new(value: usize) -> Result<Self, Error> {
        const_try!(Self::check(value));

        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: usize) -> Option<Self> {
        const_result_ok!(Self::new(value))
    }

    /// Checks if the provided value is valid for [`Self`].
    ///
    /// # Errors
    ///
    /// This function never fails when the `unsafe-length` feature is enabled.
    /// Otherwise, it returns an error containing the unsafe value provided.
    #[allow(unused_variables)]
    pub const fn check(value: usize) -> Result<(), Error> {
        #[cfg(not(feature = "unsafe-length"))]
        quick_check!(value < MIN => error!(value));

        Ok(())
    }

    /// Constructs [`Self`] without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given value is valid for [`Self`].
    ///
    /// This invariant can be checked using [`check`].
    ///
    /// [`check`]: Self::check
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
    }

    /// Returns the recommended length for the given [`Algorithm`].
    pub const fn recommended_for(algorithm: Algorithm) -> Self {
        // SAFETY: the length is known to be valid for `Self`
        // regardless of the `unsafe-length` feature.
        unsafe { Self::new_unchecked(algorithm.recommended_length()) }
    }

    /// Returns the length value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// The minimum [`Self`] value.
    #[cfg(not(feature = "unsafe-length"))]
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();
}
