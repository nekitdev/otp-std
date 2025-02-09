//! One-Time Password authentication.

pub mod core;
pub mod label;
pub mod part;
pub mod query;
pub mod scheme;
pub mod url;
pub mod utf8;

pub use core::{Auth, Owned};
pub use label::{Label, Owned as OwnedLabel};
pub use part::{Owned as OwnedPart, Part};
pub use scheme::SCHEME;
pub use url::Url;
