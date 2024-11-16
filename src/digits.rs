//! One-Time Password (OTP) digits.

use std::{fmt, num::ParseIntError, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{int, macros::const_assert};

/// The minimum digits value.
pub const MIN: u8 = 6;

/// The maximum digits value.
pub const MAX: u8 = 8;

/// The default digits value.
pub const DEFAULT: u8 = MIN;

const_assert!(MAX >= MIN);

/// Represents errors that can occur during digits creation.
///
/// This error is returned when the given value is less than [`MIN`] or greater than [`MAX`].
#[derive(Debug, Error, Diagnostic)]
#[error("expected digits in `[{MIN}, {MAX}]` range, got `{value}`")]
#[diagnostic(
    code(otp_std::digits),
    help("make sure the digits are between `{MIN}` and `{MAX}`")
)]
pub struct Error {
    /// The invalid value.
    pub value: u8,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(value: u8) -> Self {
        Self { value }
    }
}

/// Represents sources of errors that can occur when parsing [`Digits`] values.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ParseErrorSource {
    /// Invalid digits value.
    Digits(#[from] Error),
    /// Integer parse error.
    Int(#[from] int::ParseError),
}

/// Represents errors that occur when parsing [`Digits`] values.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to digits")]
#[diagnostic(
    code(otp_std::digits::parse),
    help("see the report for more information")
)]
pub struct ParseError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ParseErrorSource,
    /// The string that could not be parsed.
    pub string: String,
}

impl ParseError {
    /// Constructs [`Self`].
    pub fn new(source: ParseErrorSource, string: String) -> Self {
        Self { source, string }
    }

    /// Constructs [`Self`] from [`struct@Error`].
    pub fn digits(error: Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`int::ParseError`].
    pub fn int(error: int::ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Wraps [`ParseIntError`] into [`int::ParseError`] and constructs [`Self`] from it.
    pub fn wrap_int(error: ParseIntError, string: String) -> Self {
        Self::int(int::ParseError(error), string)
    }
}

/// Represents the number of digits in OTPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
pub struct Digits {
    value: u8,
}

impl FromStr for Digits {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::wrap_int(error, string.to_owned()))?;

        Self::new(value).map_err(|error| Self::Err::digits(error, string.to_owned()))
    }
}

impl fmt::Display for Digits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

impl TryFrom<u8> for Digits {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Digits> for u8 {
    fn from(digits: Digits) -> Self {
        digits.value
    }
}

impl Default for Digits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Digits {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given value is less than [`MIN`] or greater than [`MAX`].
    pub const fn new(value: u8) -> Result<Self, Error> {
        if value < MIN || value > MAX {
            Err(Error::new(value))
        } else {
            Ok(unsafe { Self::new_unchecked(value) })
        }
    }

    /// Constructs [`Self`] without checking the given value.
    ///
    /// # Safety
    ///
    /// The value must be greater than or equal to [`MIN`] and less than or equal to [`MAX`].
    pub const unsafe fn new_unchecked(value: u8) -> Self {
        Self { value }
    }

    /// The minimum [`Self`] value.
    pub const MIN: Self = unsafe { Self::new_unchecked(MIN) };

    /// The maximum [`Self`] value.
    pub const MAX: Self = unsafe { Self::new_unchecked(MAX) };

    /// The default [`Self`] value.
    pub const DEFAULT: Self = unsafe { Self::new_unchecked(DEFAULT) };

    /// Returns the value of wrapped in [`Self`] as [`usize`].
    pub const fn count(self) -> usize {
        self.value as usize
    }

    /// Raises `10` to the power of the value of wrapped in [`Self`].
    pub const fn power(self) -> u32 {
        10u32.pow(self.value as u32)
    }

    /// Formats the given code, padding it to the length returned from [`count`].
    ///
    /// [`count`]: Self::count
    pub fn string(self, code: u32) -> String {
        format!("{:01$}", code, self.count())
    }
}
