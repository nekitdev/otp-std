//! Time-based One-Time Password (TOTP) periods.

use std::{fmt, str::FromStr, time::Duration};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use thiserror::Error;

use crate::{
    int,
    macros::{const_result_ok, const_try, errors, quick_check},
};

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
    Int(#[from] int::ParseError),
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
    pub fn int(error: int::ParseError, string: String) -> Self {
        Self::new(error.into(), string)
    }
}

/// Represents time periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Period {
    value: u64,
}

#[cfg(feature = "serde")]
impl Serialize for Period {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Period {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;

        Self::new(value).map_err(de::Error::custom)
    }
}

errors! {
    Type = ParseError,
    Hack = $,
    int_error => int(error, string => to_owned),
    period_error => period(error, string => to_owned),
}

impl FromStr for Period {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| int_error!(int::wrap(error), string))?;

        Self::new(value).map_err(|error| period_error!(error, string))
    }
}

impl fmt::Display for Period {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
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
        period.get()
    }
}

impl Default for Period {
    fn default() -> Self {
        Self::DEFAULT
    }
}

errors! {
    Type = Error,
    Hack = $,
    error => new(value),
}

impl Period {
    /// Constructs [`Self`], if possible.
    ///
    /// # Errors
    ///
    /// See [`check`] for more information.
    ///
    /// [`check`]: Self::check
    pub const fn new(value: u64) -> Result<Self, Error> {
        const_try!(Self::check(value));

        Ok(unsafe { Self::new_unchecked(value) })
    }

    /// Similar to [`new`], but the error is discarded.
    ///
    /// [`new`]: Self::new
    pub const fn new_ok(value: u64) -> Option<Self> {
        const_result_ok!(Self::new(value))
    }

    /// Checks if the given value is valid for [`Self`].
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the given value is less than [`MIN`].
    pub const fn check(value: u64) -> Result<(), Error> {
        quick_check!(value < MIN => error!(value));

        Ok(())
    }

    /// Constructs [`Self`] without checking the given value.
    ///
    /// # Safety
    ///
    /// The given value must be at least [`MIN`].
    ///
    /// This invariant can be checked using [`check`].
    ///
    /// [`check`]: Self::check
    pub const unsafe fn new_unchecked(value: u64) -> Self {
        Self { value }
    }

    /// Returns the value wrapped in [`Self`].
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Returns the period as [`Duration`].
    pub const fn as_duration(self) -> Duration {
        Duration::from_secs(self.get())
    }

    /// The minimum [`Self`] value.
    pub const MIN: Self = Self::new_ok(MIN).unwrap();

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new_ok(DEFAULT).unwrap();
}
