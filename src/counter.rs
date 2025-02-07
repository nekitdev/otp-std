//! One-Time Password (OTP) counters.

use std::{fmt, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{
    int::{self, ParseError},
    macros::{const_option_map, errors},
};

/// The default counter value.
pub const DEFAULT: u64 = 0;

/// Represents errors that can occur when parsing counters.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to counter")]
#[diagnostic(code(otp_std::counter), help("see the report for more information"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ParseError,
    /// The string that could not be parsed.
    pub string: String,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ParseError, string: String) -> Self {
        Self { source, string }
    }
}

/// Represents counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u64", into = "u64"))]
pub struct Counter {
    value: u64,
}

errors! {
    Type = Error,
    Hack = $,
    error => new(error, string => to_owned),
}

impl FromStr for Counter {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| error!(int::wrap(error), string))?;

        Ok(Self::new(value))
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl From<u64> for Counter {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Counter> for u64 {
    fn from(counter: Counter) -> Self {
        counter.get()
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The message used for counter overflow panics.
pub const OVERFLOW: &str = "overflow";

impl Counter {
    /// Constructs [`Self`].
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Returns the value of this counter.
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Returns the incremented counter while checking for overflows.
    ///
    /// # Note
    ///
    /// Since [`Counter`] is [`Copy`], one can continue using the original counter after calling
    /// this method. So, even if [`None`] is returned, the original counter will not be dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use otp_std::Counter;
    ///
    /// let counter = Counter::new(0);
    /// let expected = Counter::new(1);
    ///
    /// assert_eq!(counter.try_next(), Some(expected));
    /// ```
    ///
    /// Returning [`None`] on overflows:
    ///
    /// ```
    /// use otp_std::Counter;
    ///
    /// let counter = Counter::new(u64::MAX);
    ///
    /// assert_eq!(counter.try_next(), None);
    /// ```
    #[must_use = "this method returns the incremented counter instead of modifying the original"]
    pub const fn try_next(self) -> Option<Self> {
        const_option_map!(self.get().checked_add(1) => Self::new)
    }

    /// Returns the incremented counter, panicking on overflows.
    ///
    /// # Panics
    ///
    /// This method will panic if the counter overflows.
    ///
    /// # Examples
    ///
    /// ```
    /// use otp_std::Counter;
    ///
    /// let counter = Counter::new(0);
    /// let expected = Counter::new(1);
    ///
    /// assert_eq!(counter.next(), expected);
    /// ```
    ///
    /// Panicking on overflows:
    ///
    /// ```should_panic
    /// use otp_std::Counter;
    ///
    /// let counter = Counter::new(u64::MAX);
    ///
    /// counter.next();
    /// ```
    #[must_use = "this method returns the incremented counter instead of modifying the original"]
    pub const fn next(self) -> Self {
        self.try_next().expect(OVERFLOW)
    }

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new(DEFAULT);
}
