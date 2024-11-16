//! HOTP (Hmac-based One-Time Password) functionality.

use bon::Builder;

#[cfg(feature = "auth")]
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "auth")]
use thiserror::Error;

#[cfg(feature = "auth")]
use url::Url;

use crate::{base::Base, counter::Counter};

#[cfg(feature = "auth")]
use crate::{auth::query::Query, base, counter};

/// Represents HOTP configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hotp<'h> {
    /// The base configuration.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub base: Base<'h>,
    /// The counter used to generate codes.
    pub counter: Counter,
}

impl<'h> Hotp<'h> {
    /// Returns the base configuration.
    pub fn base(&self) -> &Base<'h> {
        &self.base
    }

    /// Returns the mutable base configuration.
    pub fn base_mut(&mut self) -> &mut Base<'h> {
        &mut self.base
    }

    /// Consumes [`Self`], returning the base configuration.
    pub fn into_base(self) -> Base<'h> {
        self.base
    }
}

impl Hotp<'_> {
    /// Returns the current counter value.
    pub fn counter(&self) -> u64 {
        self.counter.get()
    }

    /// Increments the counter value.
    pub fn increment(&mut self) {
        self.counter = self.counter.incremented();
    }

    /// Generates the code for the current counter value.
    pub fn generate(&self) -> u32 {
        self.base.generate(self.counter())
    }

    /// Generates the string code for the current counter value.
    pub fn generate_string(&self) -> String {
        self.base.generate_string(self.counter())
    }

    /// Verifies the code for the current counter value.
    pub fn verify(&self, code: u32) -> bool {
        self.base.verify(self.counter(), code)
    }

    /// Verifies the string code for the current counter value.
    pub fn verify_string<S: AsRef<str>>(&self, code: S) -> bool {
        self.base.verify_string(self.counter(), code)
    }
}

/// The `counter` literal.
#[cfg(feature = "auth")]
pub const COUNTER: &str = "counter";

/// Represents errors returned when the counter is not found in the OTP URL.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to find counter")]
#[diagnostic(code(otp_std::hotp::counter), help("make sure the counter is present"))]
pub struct CounterNotFoundError;

/// Represents sources of errors that can occur when extracting HOTP configurations from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The base configuration could not be extracted from the OTP URL.
    Base(#[from] base::Error),
    /// The counter was not found in the OTP URL.
    CounterNotFound(#[from] CounterNotFoundError),
    /// The counter was found, but could not be parsed.
    Counter(#[from] counter::Error),
}

/// Represents errors that can occur when extracting HOTP configurations from OTP URLs.
#[cfg(feature = "auth")]
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract HOTP from OTP URL")]
#[diagnostic(
    code(otp_std::hotp::extract),
    help("see the report for more information")
)]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

#[cfg(feature = "auth")]
impl Error {
    /// Constructs [`Self`].
    pub fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`base::Error`].
    pub fn base(error: base::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`CounterNotFoundError`].
    pub fn counter_not_found(error: CounterNotFoundError) -> Self {
        Self::new(error.into())
    }

    /// Creates [`CounterNotFoundError`] and constructs [`Self`] from it.
    pub fn new_counter_not_found() -> Self {
        Self::counter_not_found(CounterNotFoundError)
    }

    /// Constructs [`Self`] from [`counter::Error`].
    pub fn counter(error: counter::Error) -> Self {
        Self::new(error.into())
    }
}

#[cfg(feature = "auth")]
impl Hotp<'_> {
    /// Applies the HOTP configuration to the given URL.
    ///
    /// Note that this method applies the base configuration on its own.
    pub fn query_for(&self, url: &mut Url) {
        self.base.query_for(url);

        let counter = self.counter.to_string();

        url.query_pairs_mut().append_pair(COUNTER, &counter);
    }

    /// Extracts the TOTP configuration from the given query.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if extraction fails.
    pub fn extract_from(query: &mut Query<'_>) -> Result<Self, Error> {
        let base = Base::extract_from(query).map_err(Error::base)?;

        let counter = query
            .remove(COUNTER)
            .ok_or_else(Error::new_counter_not_found)?
            .parse()
            .map_err(Error::counter)?;

        let hotp = Self::builder().base(base).counter(counter).build();

        Ok(hotp)
    }
}
