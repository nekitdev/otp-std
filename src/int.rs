//! Integer parsing errors.

use std::num::ParseIntError;

use miette::Diagnostic;
use thiserror::Error;

/// Wraps [`ParseIntError`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse integer")]
#[diagnostic(code(totp::int::parse), help("ensure the input is valid"))]
pub struct ParseError(#[from] pub ParseIntError);
