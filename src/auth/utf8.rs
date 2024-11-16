//! UTF-8 errors.

use std::string::FromUtf8Error;

use miette::Diagnostic;
use thiserror::Error;

/// Wraps [`FromUtf8Error`] to provide diagnostics.
#[derive(Debug, Error, Diagnostic)]
#[error("invalid utf-8 encountered when decoding")]
#[diagnostic(
    code(opt_std::auth::utf8),
    help("make sure the part decodes to valid utf-8")
)]
pub struct Error(#[from] pub FromUtf8Error);
