//! Secrets used in OTP generation.

pub mod encoding;
pub mod length;

#[cfg(feature = "generate-secret")]
pub mod generate;

pub mod core;

pub use length::Length;

pub use core::{Error, Owned, Secret};
