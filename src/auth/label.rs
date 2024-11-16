//! Authentication labels.

use std::{borrow::Cow, fmt, str::FromStr, string::FromUtf8Error};

use bon::Builder;
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use url::Url;
use urlencoding::decode;

use crate::auth::{
    part::{self, Part, SEPARATOR},
    utf8,
};

/// Represents errors that occur when the label is empty.
#[derive(Debug, Error, Diagnostic)]
#[error("empty label encountered")]
#[diagnostic(
    code(otp_std::auth::label::empty),
    help("make sure the label is non-empty")
)]
pub struct EmptyError;

/// Represents sources of errors that can occur when parsing labels.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ParseErrorSource {
    /// The label is empty.
    Empty(#[from] EmptyError),
    /// The label part is invalid.
    Part(#[from] part::Error),
}

/// Represents errors that occur when parsing labels.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to parse label")]
#[diagnostic(
    code(otp_std::auth::label),
    help("make sure the label is formatted correctly")
)]
pub struct ParseError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ParseErrorSource,
}

impl ParseError {
    /// Constructs [`Self`].
    pub const fn new(source: ParseErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`EmptyError`].
    pub fn empty(error: EmptyError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`part::Error`].
    pub fn part(error: part::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`EmptyError`] and constructs [`Self`] from it.
    pub fn new_empty() -> Self {
        Self::empty(EmptyError)
    }
}

/// Represents authentication labels.
#[derive(Debug, Clone, PartialEq, Eq, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Label<'l> {
    /// The authentication issuer.
    pub issuer: Option<Part<'l>>,
    /// The authentication user.
    pub user: Part<'l>,
}

impl fmt::Display for Label<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(issuer) = self.issuer.as_ref() {
            issuer.fmt(formatter)?;

            formatter.write_str(SEPARATOR)?;
        };

        self.user.fmt(formatter)
    }
}

impl FromStr for Label<'_> {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.is_empty() {
            return Err(Self::Err::new_empty());
        }

        if let Some((issuer_part, user_part)) = string.split_once(SEPARATOR) {
            let issuer = issuer_part.parse().map_err(Self::Err::part)?;
            let user = user_part.parse().map_err(Self::Err::part)?;

            Ok(Self::builder().issuer(issuer).user(user).build())
        } else {
            let user = string.parse().map_err(Self::Err::part)?;

            Ok(Self::builder().user(user).build())
        }
    }
}

/// Represents sources of errors that can occur when decoding labels.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum DecodeErrorSource {
    /// The label is not valid UTF-8.
    Utf8(#[from] utf8::Error),
    /// The label is otherwise not valid.
    Parse(#[from] ParseError),
}

/// Represents errors that occur when decoding labels.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to decode label")]
#[diagnostic(
    code(otp_std::auth::label::decode),
    help("make sure the label is correctly formatted")
)]
pub struct DecodeError {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: DecodeErrorSource,
}

impl DecodeError {
    /// Constructs [`Self`].
    pub const fn new(source: DecodeErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`utf8::Error`].
    pub fn utf8(error: utf8::Error) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`ParseError`].
    pub fn label(error: ParseError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`utf8::Error`] and constructs [`Self`] from it.
    pub fn new_utf8(error: FromUtf8Error) -> Self {
        Self::utf8(utf8::Error(error))
    }
}

impl Label<'_> {
    /// Decodes the label from the given string.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the label could not be decoded.
    pub fn decode<S: AsRef<str>>(string: S) -> Result<Self, DecodeError> {
        let string = string.as_ref();

        let decoded = decode(string).map_err(DecodeError::new_utf8)?;

        decoded.parse().map_err(DecodeError::label)
    }
}

impl Label<'_> {
    /// Encodes the label.
    pub fn encode(&self) -> Cow<'_, str> {
        let encoded_user = self.user.encode();

        if let Some(issuer) = self.issuer.as_ref() {
            let encoded_issuer = issuer.encode();

            let string = format!("{encoded_issuer}{SEPARATOR}{encoded_user}");

            Cow::Owned(string)
        } else {
            encoded_user
        }
    }
}

/// The `issuer` literal.
#[cfg(feature = "auth")]
pub const ISSUER: &str = "issuer";

#[cfg(feature = "auth")]
impl Label<'_> {
    /// Applies the label to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        if let Some(issuer) = self.issuer.as_ref() {
            url.query_pairs_mut()
                .append_pair(ISSUER, issuer.encode().as_ref());
        };
    }
}
