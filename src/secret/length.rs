//! Secret lengths.

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{algorithm::Algorithm, macros::const_result_ok};

use crate::macros::{errors, quick_error};

/// The default (and recommended) secret length.
pub const DEFAULT: usize = 20;

/// The minimum allowed secret length.
#[cfg(feature = "unsafe-length")]
pub const MIN: usize = 0;

/// The minimum allowed secret length.
#[cfg(not(feature = "unsafe-length"))]
pub const MIN: usize = 16;

/// Represents errors returned when unsafe lengths are used.
///
/// Note that this error is never returned when the `unsafe-length` feature is enabled.
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

impl Error {
    /// Constructs [`Self`].
    pub const fn new(length: usize) -> Self {
        Self { length }
    }
}

/// Represents OTP secret lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "usize", into = "usize"))]
pub struct Length {
    value: usize,
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
    /// This function never fails when the `unsafe-length` feature is enabled.
    /// Otherwise, it returns an error containing the unsafe value provided.
    pub const fn new(value: usize) -> Result<Self, Error> {
        quick_error!(value < MIN => error!(value));

        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: usize) -> Option<Self> {
        const_result_ok!(Self::new(value))
    }

    /// Constructs [`Self`] without checking the length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given value is valid for [`Self`].
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
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();
}
