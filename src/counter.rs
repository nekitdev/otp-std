//! One-Time Password (OTP) counters.

use std::{fmt, num::ParseIntError, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::int::ParseError;

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
    pub fn new(source: ParseError, string: String) -> Self {
        Self { source, string }
    }

    /// Wraps [`ParseIntError`] into [`ParseError`] and constructs [`Self`] from it.
    pub fn wrap(error: ParseIntError, string: String) -> Self {
        Self::new(error.into(), string)
    }
}

/// Represents counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u64", into = "u64"))]
pub struct Counter {
    value: u64,
}

impl FromStr for Counter {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::wrap(error, string.to_owned()))?;

        Ok(Self::new(value))
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

impl From<u64> for Counter {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Counter> for u64 {
    fn from(counter: Counter) -> Self {
        counter.value
    }
}

impl Counter {
    /// Constructs [`Self`].
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Returns the value of this counter.
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Returns the incremented counter.
    pub const fn incremented(self) -> Self {
        Self::new(self.value + 1)
    }
}
