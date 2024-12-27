//! Secret lengths.

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

/// The default (and recommended) secret length.
pub const DEFAULT: usize = 20;

/// The minimum allowed secret length.
#[cfg(not(feature = "unsafe-length"))]
pub const MIN: usize = 16;

/// Errors are never returned when `unsafe-length` is enabled.
#[cfg(feature = "unsafe-length")]
#[derive(Debug, Error, Diagnostic)]
pub enum Error {}

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
        length.value
    }
}

impl Default for Length {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Length {
    /// Constructs [`Self`] without checking the length.
    ///
    /// # Errors
    ///
    /// This function never fails when `unsafe-length` is enabled.
    #[cfg(feature = "unsafe-length")]
    pub const fn new(value: usize) -> Result<Self, Error> {
        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// This function returns [`struct@Error`] if the given value is less than [`MIN`].
    #[cfg(not(feature = "unsafe-length"))]
    pub const fn new(value: usize) -> Result<Self, Error> {
        if value < MIN {
            Err(Error::new(value))
        } else {
            Ok(unsafe { Self::new_unchecked(value) })
        }
    }

    /// Constructs [`Self`] without checking the length.
    ///
    /// # Safety
    pub const unsafe fn new_unchecked(value: usize) -> Self {
        Self { value }
    }

    /// Returns the length value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// The minimum [`Self`] value.
    #[cfg(not(feature = "unsafe-length"))]
    pub const MIN: Self = unsafe { Self::new_unchecked(MIN) };

    /// The default [`Self`] value.
    pub const DEFAULT: Self = unsafe { Self::new_unchecked(DEFAULT) };
}
