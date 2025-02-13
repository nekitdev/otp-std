//! One-Time Password (OTP) digits.

use std::{fmt, str::FromStr};

use const_macros::{const_early, const_ok, const_try};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::{int, macros::errors};

/// The minimum digits value.
pub const MIN: u8 = 6;

/// The maximum digits value.
pub const MAX: u8 = 8;

/// The default digits value.
pub const DEFAULT: u8 = MIN;

/// Represents errors that can occur during digits creation.
///
/// This error is returned when the given value is less than [`MIN`] or greater than [`MAX`].
#[derive(Debug, Error, Diagnostic)]
#[error("expected digits in `[{MIN}, {MAX}]` range, got `{value}`")]
#[diagnostic(
    code(otp_std::digits),
    help("make sure the digits are at least `{MIN}` and at most `{MAX}`")
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
    pub const fn new(source: ParseErrorSource, string: String) -> Self {
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
}

/// Represents the number of digits in OTPs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digits {
    value: u8,
}

#[cfg(feature = "serde")]
impl Serialize for Digits {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Digits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

errors! {
    Type = ParseError,
    Hack = $,
    digits_error => digits(error, string => to_owned),
    int_error => int(error, string => to_owned),
}

impl FromStr for Digits {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| int_error!(int::wrap(error), string))?;

        Self::new(value).map_err(|error| digits_error!(error, string))
    }
}

impl fmt::Display for Digits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
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
        digits.get()
    }
}

impl Default for Digits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

errors! {
    Type = Error,
    Hack = $,
    error => new(value),
}

impl Digits {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// See [`check`] for more information.
    ///
    /// [`check`]: Self::check
    pub const fn new(value: u8) -> Result<Self, Error> {
        const_try!(Self::check(value));

        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: u8) -> Option<Self> {
        const_ok!(Self::new(value))
    }

    /// Checks if the provided value is valid for [`Self`].
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given value is less than [`MIN`] or greater than [`MAX`].
    pub const fn check(value: u8) -> Result<(), Error> {
        const_early!(value < MIN || value > MAX => error!(value));

        Ok(())
    }

    /// Constructs [`Self`] without checking the given value.
    ///
    /// # Safety
    ///
    /// The value must be greater than or equal to [`MIN`] and less than or equal to [`MAX`].
    ///
    /// This invariant can be checked using [`check`].
    ///
    /// [`check`]: Self::check
    pub const unsafe fn new_unchecked(value: u8) -> Self {
        Self { value }
    }

    /// The minimum [`Self`] value.
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The maximum [`Self`] value.
    pub const MAX: Self = Self::new_ok(MAX).unwrap();

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();

    /// Returns the value wrapped in [`Self`] as [`usize`].
    pub const fn count(self) -> usize {
        self.get() as usize
    }

    /// Returns the value wrapped in [`Self`].
    pub const fn get(self) -> u8 {
        self.value
    }

    /// Raises `10` to the power of the value wrapped in [`Self`].
    pub const fn power(self) -> u32 {
        10u32.pow(self.get() as u32)
    }

    /// Formats the given code, padding it to the length returned from [`count`].
    ///
    /// [`count`]: Self::count
    pub fn string(self, code: u32) -> String {
        format!("{code:0count$}", count = self.count())
    }
}
