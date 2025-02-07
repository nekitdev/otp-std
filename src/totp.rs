//! Time-based One-Time Password (TOTP) functionality.

use bon::Builder;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "auth")]
use miette::Diagnostic;

#[cfg(feature = "auth")]
use thiserror::Error;

#[cfg(feature = "auth")]
use crate::auth::url::Url;

use crate::{
    base::Base,
    period::Period,
    skew::Skew,
    time::{self, expect_now, now},
};

#[cfg(feature = "auth")]
use crate::{auth::query::Query, base, period};

/// Represents TOTP configurations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Totp<'t> {
    /// The base configuration.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub base: Base<'t>,
    /// The skew to apply.
    #[builder(default)]
    #[cfg_attr(feature = "serde", serde(default))]
    pub skew: Skew,
    /// The period to use.
    #[builder(default)]
    #[cfg_attr(feature = "serde", serde(default))]
    pub period: Period,
}

impl<'t> Totp<'t> {
    /// Returns the base configuration.
    pub const fn base(&self) -> &Base<'t> {
        &self.base
    }

    /// Returns the mutable base configuration.
    pub fn base_mut(&mut self) -> &mut Base<'t> {
        &mut self.base
    }

    /// Consumes [`Self`], returning the base configuration.
    pub fn into_base(self) -> Base<'t> {
        self.base
    }
}

impl Totp<'_> {
    /// Returns the input value corresponding to the given time.
    pub const fn input_at(&self, time: u64) -> u64 {
        time / self.period.get()
    }

    /// Returns the time corresponding to the next period from the given time.
    pub const fn next_period_at(&self, time: u64) -> u64 {
        let period = self.period.get();

        (time / period + 1) * period
    }

    /// Tries to return the time corresponding to the next period from the current time.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_next_period(&self) -> Result<u64, time::Error> {
        now().map(|time| self.next_period_at(time))
    }

    /// Returns the time corresponding to the next period from the current time.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn next_period(&self) -> u64 {
        self.next_period_at(expect_now())
    }

    /// Returns the time to live of the code for the given time.
    pub const fn time_to_live_at(&self, time: u64) -> u64 {
        let period = self.period.get();

        period - time % period
    }

    /// Tries to return the time to live of the code for the current time.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_time_to_live(&self) -> Result<u64, time::Error> {
        now().map(|time| self.time_to_live_at(time))
    }

    /// Returns the time to live of the code for the current time.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn time_to_live(&self) -> u64 {
        self.time_to_live_at(expect_now())
    }

    /// Generates the code for the given time.
    pub fn generate_at(&self, time: u64) -> u32 {
        self.base.generate(self.input_at(time))
    }

    /// Generates the string code for the given time.
    pub fn generate_string_at(&self, time: u64) -> String {
        self.base.generate_string(self.input_at(time))
    }

    /// Tries to generate the code for the current time.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_generate(&self) -> Result<u32, time::Error> {
        now().map(|time| self.generate_at(time))
    }

    /// Generates the code for the current time.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn generate(&self) -> u32 {
        self.generate_at(expect_now())
    }

    /// Tries to generate the string code for the current time.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_generate_string(&self) -> Result<String, time::Error> {
        now().map(|time| self.generate_string_at(time))
    }

    /// Generates the string code for the current time.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn generate_string(&self) -> String {
        self.generate_string_at(expect_now())
    }

    /// Verifies the given code for the given time.
    pub fn verify_exact_at(&self, time: u64, code: u32) -> bool {
        self.base.verify(self.input_at(time), code)
    }

    /// Verifies the given string code for the given time.
    pub fn verify_string_exact_at<S: AsRef<str>>(&self, time: u64, code: S) -> bool {
        self.base.verify_string(self.input_at(time), code)
    }

    /// Tries to verify the given code for the current time *exactly*.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_verify_exact(&self, code: u32) -> Result<bool, time::Error> {
        now().map(|time| self.verify_exact_at(time, code))
    }

    /// Verifies the given code for the current time *exactly*.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn verify_exact(&self, code: u32) -> bool {
        self.verify_exact_at(expect_now(), code)
    }

    /// Tries to verify the given string code for the current time *exactly*.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_verify_string_exact<S: AsRef<str>>(&self, code: S) -> Result<bool, time::Error> {
        now().map(|time| self.verify_string_exact_at(time, code))
    }

    /// Verifies the given string code for the current time *exactly*.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn verify_string_exact<S: AsRef<str>>(&self, code: S) -> bool {
        self.verify_string_exact_at(expect_now(), code)
    }

    /// Verifies the given code for the given time, accounting for *skews*.
    pub fn verify_at(&self, time: u64, code: u32) -> bool {
        self.skew
            .apply(self.input_at(time))
            .any(|input| self.base.verify(input, code))
    }

    fn verify_str_at(&self, time: u64, code: &str) -> bool {
        self.skew
            .apply(self.input_at(time))
            .any(|input| self.base.verify_string(input, code))
    }

    /// Verifies the given string code for the given time, accounting for *skews*.
    pub fn verify_string_at<S: AsRef<str>>(&self, time: u64, code: S) -> bool {
        self.verify_str_at(time, code.as_ref())
    }

    /// Tries to verify the given code for the current time, accounting for *skews*.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_verify(&self, code: u32) -> Result<bool, time::Error> {
        now().map(|time| self.verify_at(time, code))
    }

    /// Verifies the given code for the current time, accounting for *skews*.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn verify(&self, code: u32) -> bool {
        self.verify_at(expect_now(), code)
    }

    /// Tries to verify the given string code for the current time, accounting for *skews*.
    ///
    /// # Errors
    ///
    /// Returns [`time::Error`] if the system time is before the epoch.
    pub fn try_verify_string<S: AsRef<str>>(&self, code: S) -> Result<bool, time::Error> {
        now().map(|time| self.verify_string_at(time, code))
    }

    /// Verifies the given string code for the current time, accounting for *skews*.
    ///
    /// # Panics
    ///
    /// Panics if the system time is before the epoch.
    pub fn verify_string<S: AsRef<str>>(&self, code: S) -> bool {
        self.verify_string_at(expect_now(), code)
    }
}

/// The `period` literal.
#[cfg(feature = "auth")]
pub const PERIOD: &str = "period";

/// Represents sources of errors that can occur when extracting TOTP configurations
/// from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The base configuration could not be extracted.
    Base(#[from] base::Error),
    /// The period could not be parsed.
    Period(#[from] period::ParseError),
}

/// Represents errors that can occur when extracting TOTP configurations from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract TOTP from OTP URL")]
#[diagnostic(code(otp_std::totp), help("see the report for more information"))]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

#[cfg(feature = "auth")]
impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`base::Error`].
    pub fn base(error: base::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`period::ParseError`].
    pub fn period(error: period::ParseError) -> Self {
        Self::new(error.into())
    }
}

#[cfg(feature = "auth")]
impl Totp<'_> {
    /// Applies the HOTP configuration to the given URL.
    ///
    /// Note that this method applies the base configuration on its own.
    pub fn query_for(&self, url: &mut Url) {
        self.base.query_for(url);

        let period = self.period.to_string();

        url.query_pairs_mut().append_pair(PERIOD, &period);
    }

    /// Extracts the TOTP configuration from the given query.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if extraction fails.
    pub fn extract_from(query: &mut Query<'_>) -> Result<Self, Error> {
        let base = Base::extract_from(query).map_err(Error::base)?;

        let maybe_period = query
            .remove(PERIOD)
            .map(|string| string.parse())
            .transpose()
            .map_err(Error::period)?;

        let totp = Self::builder()
            .base(base)
            .maybe_period(maybe_period)
            .build();

        Ok(totp)
    }
}

/// Represents owned [`Totp`].
pub type Owned = Totp<'static>;

impl Totp<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        Owned::builder()
            .base(self.base.into_owned())
            .skew(self.skew)
            .period(self.period)
            .build()
    }
}
