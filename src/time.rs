//! Current time functionality.
//!
//! This module provides the [`now`] function to fetch the current time as seconds since the epoch.
//! Note that [`now`] can return [`struct@Error`] in case the current time is before the epoch.

use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use miette::Diagnostic;
use thiserror::Error;

/// The error message for when the system time is before the epoch.
pub const CURRENT_TIME_BEFORE_EPOCH: &str = "current time is before the epoch";

/// Wraps [`SystemTimeError`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("system time is before epoch")]
#[diagnostic(code(otp_std::time), help("see the report for more information"))]
pub struct Error(#[from] pub SystemTimeError);

/// Returns the current time as seconds since the epoch.
///
/// # Errors
///
/// Returns [`struct@Error`] if the system time is before the epoch.
pub fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(Error)
}

/// Similar to [`now`], but panics if the current time is before the epoch.
///
/// # Panics
///
/// Panics if the current time is before the epoch.
pub fn expect_now() -> u64 {
    now().expect(CURRENT_TIME_BEFORE_EPOCH)
}
