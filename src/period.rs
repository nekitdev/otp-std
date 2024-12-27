//! Time periods.

use std::{fmt, num::ParseIntError, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

/// The minimum period value.
pub const MIN: u64 = 1;

/// The default period value.
pub const DEFAULT: u64 = 30;

/// Represents errors that can occur during period creation.
///
/// This error is returned when the given value is less than [`MIN`].
#[derive(Debug, Error, Diagnostic)]
#[error("expected period to be at least `{MIN}`, got `{value}`")]
#[diagnostic(
    code(otp_std::period),
    help("make sure the period is at least `{MIN}`")
)]
pub struct Error {
    /// The invalid value.
    pub value: u64,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

/// Represents sources of errors that can occur when parsing [`Period`] values.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ParseErrorSource {
    /// Invalid period value.
    Period(#[from] Error),
    /// Integer parse error.
    Int(#[from] crate::int::ParseError),
}

/// Represents errors that occur when parsing [`Period`] values.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to digits")]
#[diagnostic(
    code(otp_std::period::parse),
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
    pub fn period(error: Error, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Constructs [`Self`] from [`int::ParseError`].
    ///
    /// [`int::ParseError`]: crate::int::ParseError
    pub fn int(error: crate::int::ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }

    /// Wraps [`ParseIntError`] into [`int::ParseError`] and constructs [`Self`] from it.
    ///
    /// [`int::ParseError`]: crate::int::ParseError
    pub fn wrap_int(error: ParseIntError, string: String) -> Self {
        Self::int(crate::int::ParseError(error), string)
    }
}

/// Represents time periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u64", into = "u64"))]
pub struct Period {
    value: u64,
}

impl FromStr for Period {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::wrap_int(error, string.to_owned()))?;

        Self::new(value).map_err(|error| Self::Err::period(error, string.to_owned()))
    }
}

impl fmt::Display for Period {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

impl TryFrom<u64> for Period {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Period> for u64 {
    fn from(period: Period) -> Self {
        period.value
    }
}

impl Default for Period {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Period {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given value is less than [`MIN`].
    pub const fn new(value: u64) -> Result<Self, Error> {
        if value < MIN {
            Err(Error::new(value))
        } else {
            Ok(unsafe { Self::new_unchecked(value) })
        }
    }

    /// Constructs [`Self`] without checking the given value.
    ///
    /// # Safety
    ///
    /// The given value must be at least [`MIN`].
    pub const unsafe fn new_unchecked(value: u64) -> Self {
        Self { value }
    }

    /// Returns the value wrapped in [`Self`].
    pub const fn get(self) -> u64 {
        self.value
    }

    /// The minimum [`Self`] value.
    pub const MIN: Self = unsafe { Self::new_unchecked(MIN) };

    /// The default [`Self`] value.
    pub const DEFAULT: Self = unsafe { Self::new_unchecked(DEFAULT) };
}
