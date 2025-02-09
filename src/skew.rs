//! Time-based One-Time Password (TOTP) skews.

use std::{fmt, iter::once, str::FromStr};

use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{
    int::{self, ParseError},
    macros::errors,
};

/// The disabled skew value.
pub const DISABLED: u64 = 0;

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

errors! {
    Type = Self::Err,
    Hack = $,
    error => new(error, string => to_owned),
}

impl FromStr for Skew {
    type Err = Error;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let value = string
            .parse()
            .map_err(|error| error!(int::wrap(error), string))?;

        Ok(Self::new(value))
    }
}

impl fmt::Display for Skew {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

impl From<u64> for Skew {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Skew> for u64 {
    fn from(skew: Skew) -> Self {
        skew.get()
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

    /// Returns the value wrapped in [`Self`].
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Returns the disabled [`Self`].
    pub const fn disabled() -> Self {
        Self::DISABLED
    }

    /// Applies the skew to the given value.
    ///
    /// Given some skew `s` and value `n`, this method returns an iterator that yields
    ///
    /// ```text
    /// n - s, n - s + 1, ..., n - 1, n, n + 1, ..., n + s - 1, n + s
    /// ```
    ///
    /// # Note
    ///
    /// In case of overflows, the iterator will skip the values that would cause them.
    ///
    /// # Examples
    ///
    /// Using zero to only accept the *exact* value:
    ///
    /// ```
    /// use otp_std::Skew;
    ///
    /// let skew = Skew::new(0);
    ///
    /// let mut values = skew.apply(13);
    ///
    /// assert_eq!(values.next(), Some(13));
    /// assert_eq!(values.next(), None);
    /// ```
    ///
    /// Using one:
    ///
    /// ```
    /// use otp_std::Skew;
    ///
    /// let skew = Skew::new(1);
    ///
    /// let mut values = skew.apply(13);
    ///
    /// assert_eq!(values.next(), Some(12));
    /// assert_eq!(values.next(), Some(13));
    /// assert_eq!(values.next(), Some(14));
    /// assert_eq!(values.next(), None);
    /// ```
    ///
    /// Overflow handling:
    ///
    /// ```rust
    /// use otp_std::Skew;
    ///
    /// let skew = Skew::new(1);
    ///
    /// let value = u64::MAX;
    ///
    /// let mut values = skew.apply(value);
    ///
    /// assert_eq!(values.next(), Some(value - 1));
    /// assert_eq!(values.next(), Some(value));
    /// assert_eq!(values.next(), None);
    /// ```
    pub fn apply(self, value: u64) -> impl Iterator<Item = u64> {
        let sub = (1..=self.get()).filter_map(move |offset| value.checked_sub(offset));

        let add = (1..=self.get()).filter_map(move |offset| value.checked_add(offset));

        sub.rev().chain(once(value)).chain(add)
    }

    /// The disabled [`Self`] value.
    pub const DISABLED: Self = Self::new(DISABLED);

    /// The default [`Self`] value.
    pub const DEFAULT: Self = Self::new(DEFAULT);
}
