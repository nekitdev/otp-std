//! Authentication labels.

use std::{fmt, str::FromStr};

use bon::Builder;
use miette::Diagnostic;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{
    auth::{
        part::{self, Part, SEPARATOR},
        query::Query,
        url::{self, Url},
        utf8,
    },
    macros::{errors, quick_check},
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Label<'l> {
    /// The authentication issuer.
    pub issuer: Option<Part<'l>>,
    /// The authentication user.
    pub user: Part<'l>,
}

/// Represents `(issuer, user)` parts of the label.
pub type Parts<'p> = (Option<Part<'p>>, Part<'p>);

/// Represents owned [`Parts`].
pub type OwnedParts = Parts<'static>;

impl<'l> Label<'l> {
    /// Constructs [`Self`] from parts.
    pub fn from_parts(parts: Parts<'l>) -> Self {
        let (issuer, user) = parts;

        Self::builder().maybe_issuer(issuer).user(user).build()
    }

    /// Consumes [`Self`], returning the contained parts.
    pub fn into_parts(self) -> Parts<'l> {
        (self.issuer, self.user)
    }
}

impl<'p> From<Parts<'p>> for Label<'p> {
    fn from(parts: Parts<'p>) -> Self {
        Self::from_parts(parts)
    }
}

impl<'l> From<Label<'l>> for Parts<'l> {
    fn from(label: Label<'l>) -> Self {
        label.into_parts()
    }
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

errors! {
    Type = ParseError,
    Hack = $,
    empty_error => new_empty(),
}

impl FromStr for Label<'_> {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        quick_check!(string.is_empty() => empty_error!());

        if let Some((issuer_string, user_string)) = string.split_once(SEPARATOR) {
            let issuer = issuer_string.parse().map_err(Self::Err::part)?;
            let user = user_string.parse().map_err(Self::Err::part)?;

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
}

impl Label<'_> {
    /// Decodes the label from the given string.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the label could not be decoded.
    pub fn decode<S: AsRef<str>>(string: S) -> Result<Self, DecodeError> {
        let string = string.as_ref();

        let decoded = url::decode(string)
            .map_err(utf8::wrap)
            .map_err(DecodeError::utf8)?;

        decoded.parse().map_err(DecodeError::label)
    }
}

impl Label<'_> {
    /// Encodes the label.
    pub fn encode(&self) -> String {
        self.to_string()
    }
}

/// Represnets errors that can occur on issuer mismatch.
#[derive(Debug, Error, Diagnostic)]
#[error("issuer mismatch: `{label}` in label, `{query}` in query")]
#[diagnostic(
    code(otp_std::auth::label::mismatch),
    help("if the issuer is present both in the label and the query, they must match")
)]
pub struct MismatchError {
    /// The label issuer.
    pub label: String,
    /// The query issuer.
    pub query: String,
}

impl MismatchError {
    /// Constructs [`Self`].
    pub const fn new(label: String, query: String) -> Self {
        Self { label, query }
    }
}

errors! {
    Type = MismatchError,
    Hack = $,
    mismatch_error => new(label => into_owned, query => into_owned),
}

/// Checks whether the label issuer and the query issuer match, provided both are present.
///
/// This function returns either the label issuer or the query issuer.
///
/// # Errors
///
/// Returns [`MismatchError`] if the both issuers are present and do not match.
pub fn try_match<'p>(
    label_issuer: Option<Part<'p>>,
    query_issuer: Option<Part<'p>>,
) -> Result<Option<Part<'p>>, MismatchError> {
    match (label_issuer, query_issuer) {
        (Some(label), Some(query)) if label != query => {
            Err(mismatch_error!(label.get(), query.get()))
        }
        (label_option, query_option) => Ok(label_option.or(query_option)),
    }
}

/// Represents sources of errors that can occur when extracting labels.
#[derive(Debug, Error, Diagnostic)]
#[error(transparent)]
#[diagnostic(transparent)]
pub enum ErrorSource {
    /// The label could not be decoded.
    Decode(#[from] DecodeError),
    /// The issuer could not be decoded.
    Issuer(#[from] part::DecodeError),
    /// The label and query issuers do not match.
    Mismatch(#[from] MismatchError),
}

/// Represents errors that can occur when extracting labels.
#[derive(Debug, Error, Diagnostic)]
#[error("failed to extract label from OTP URL")]
#[diagnostic(
    code(otp_std::auth::label),
    help("see the report for more information")
)]
pub struct Error {
    /// The source of this error.
    #[source]
    #[diagnostic_source]
    pub source: ErrorSource,
}

impl Error {
    /// Constructs [`Self`].
    pub const fn new(source: ErrorSource) -> Self {
        Self { source }
    }

    /// Constructs [`Self`] from [`DecodeError`].
    pub fn decode(error: DecodeError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`MismatchError`].
    pub fn mismatch(error: MismatchError) -> Self {
        Self::new(error.into())
    }

    /// Constructs [`Self`] from [`part::DecodeError`].
    pub fn issuer(error: part::DecodeError) -> Self {
        Self::new(error.into())
    }
}

/// The `issuer` literal.
pub const ISSUER: &str = "issuer";

/// The `/` literal.
pub const SLASH: &str = "/";

impl Label<'_> {
    /// Applies the label to the given URL.
    pub fn query_for(&self, url: &mut Url) {
        if let Some(issuer) = self.issuer.as_ref() {
            url.query_pairs_mut()
                .append_pair(ISSUER, issuer.encode().as_ref());
        };
    }

    /// Extracts [`Self`] from the given query and URL.
    ///
    /// # Errors
    ///
    /// Returns [`struct@Error`] if the label can not be extracted.
    pub fn extract_from(query: &mut Query<'_>, url: &Url) -> Result<Self, Error> {
        let path = url.path().trim_start_matches(SLASH);

        let label = Self::decode(path).map_err(Error::decode)?;

        // we will need to reconstruct the label
        let (label_issuer, user) = label.into_parts();

        let query_issuer = query
            .remove(ISSUER)
            .map(Part::decode)
            .transpose()
            .map_err(Error::issuer)?;

        let issuer = try_match(label_issuer, query_issuer).map_err(Error::mismatch)?;

        Ok(Self::from_parts((issuer, user)))
    }
}

/// Represents owned [`Label`].
pub type Owned = Label<'static>;

impl Label<'_> {
    /// Converts [`Self`] into [`Owned`].
    pub fn into_owned(self) -> Owned {
        Owned::builder()
            .maybe_issuer(self.issuer.map(Part::into_owned))
            .user(self.user.into_owned())
            .build()
    }
}
