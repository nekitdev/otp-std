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
pub use secret::{Length, Owned as OwnedSecret, Secret};
pub use skew::Skew;

pub mod time;

pub use time::{expect_now, now};

pub mod int;

pub mod base;
pub mod hotp;
pub mod totp;

pub use base::{Base, Owned as OwnedBase};
pub use hotp::{Hotp, Owned as OwnedHotp};
pub use totp::{Owned as OwnedTotp, Totp};

pub mod otp;

pub use otp::{Otp, Owned as OwnedOtp, Type};

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "auth")]
pub use auth::{Auth, Label, Owned as OwnedAuth, OwnedLabel, OwnedPart, Part};

pub mod macros;
