//! Generating and checking one-time passwords.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod algorithm;
pub mod counter;
pub mod digits;
pub mod period;
pub mod secret;
pub mod skew;

pub use algorithm::Algorithm;
pub use counter::Counter;
pub use digits::Digits;
pub use period::Period;
pub use secret::{Length, Secret};
pub use skew::Skew;

pub mod time;

pub use time::{expect_now, now};

pub mod int;

pub mod base;
pub mod hotp;
pub mod totp;

pub use base::Base;
pub use hotp::Hotp;
pub use totp::Totp;

pub mod otp;

pub use otp::{Otp, Type};

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "auth")]
pub use auth::{Auth, Label, Part};

pub mod macros;
