//! URL queries.

use std::{borrow::Cow, collections::HashMap};

/// Represents URL queries.
pub type Query<'q> = HashMap<Cow<'q, str>, Cow<'q, str>>;
