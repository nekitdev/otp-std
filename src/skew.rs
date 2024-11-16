//! Value skews.

use std::{fmt, iter::once, num::ParseIntError, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::int::ParseError;

/// The default skew value.
pub const DEFAULT: u64 = 1;

/// Represents errors that can occur when parsing skews.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse `{string}` to skew")]
#[diagnostic(code(otp_std::skew), help("see the report for more information"))]
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

    /// Wraps [`ParseIntError`] into [`ParseError`] and constructs [`Self`].
    pub const fn new_wrap(error: ParseIntError, string: String) -> Self {
        Self::new(ParseError(error), string)
    }
}

/// Represents value skews (see [`apply`] for more information).
///
/// [`apply`]: Self::apply
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(from = "u64", into = "u64"))]
pub struct Skew {
    value: u64,
}

impl FromStr for Skew {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| Self::Err::new_wrap(error, string.to_owned()))?;

        Ok(Self::new(value))
    }
}

impl fmt::Display for Skew {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(formatter)
    }
}

impl From<u64> for Skew {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Skew> for u64 {
    fn from(skew: Skew) -> Self {
        skew.value
    }
}

impl Default for Skew {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Skew {
    /// Constructs [`Self`].
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    /// Gets the value wrapped in [`Self`].
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Applies the skew to the given value.
    ///
    /// Given some skew `s` and value `n`, this method returns an iterator that yields
    ///
    /// ```text
    /// n - s, n - s + 1, ..., n - 1, n, n + 1, ..., n + s - 1, n + s
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use otp_std::Skew;
    ///
    /// let skew = Skew::new(1);
    ///
    /// let value = 13;
    ///
    /// let mut values = skew.apply(value);
    ///
    /// assert_eq!(values.next(), Some(12));
    /// assert_eq!(values.next(), Some(13));
    /// assert_eq!(values.next(), Some(14));
    /// assert_eq!(values.next(), None);
    /// ```
    pub fn apply(self, value: u64) -> impl Iterator<Item = u64> {
        let add = (1..=self.value).filter_map(move |offset| value.checked_add(offset));
        let sub = (1..=self.value).filter_map(move |offset| value.checked_sub(offset));

        sub.rev().chain(once(value)).chain(add)
    }

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new(DEFAULT);
}

#[cfg(test)]
mod tests {
    use super::Skew;

    #[test]
    fn test_zero() {
        let skew = Skew::new(0);

        let value = 13;

        let mut values = skew.apply(value);

        assert_eq!(values.next(), Some(value));
        assert_eq!(values.next(), None);
    }

    #[test]
    fn test_one() {
        let skew = Skew::new(1);

        let value = 13;

        let mut values = skew.apply(value);

        assert_eq!(values.next(), Some(value - 1));
        assert_eq!(values.next(), Some(value));
        assert_eq!(values.next(), Some(value + 1));

        assert_eq!(values.next(), None);
    }

    #[test]
    fn test_overflow() {}

    #[test]
    fn test_underflow() {}
}
