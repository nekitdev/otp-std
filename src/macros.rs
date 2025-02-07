//! Various macros used by this crate.

pub(crate) mod import {
    pub use std::{option::Option, result::Result};
}

macro_rules! const_result_ok {
    ($result: expr) => {
        match $result {
            $crate::macros::import::Result::Ok(value) => {
                $crate::macros::import::Option::Some(value)
            }
            $crate::macros::import::Result::Err(_) => $crate::macros::import::Option::None,
        }
    };
}

pub(crate) use const_result_ok;

macro_rules! const_option_map {
    ($option: expr => $function: expr) => {
        match $option {
            $crate::macros::import::Option::Some(value) => {
                $crate::macros::import::Option::Some($function(value))
            }
            $crate::macros::import::Option::None => $crate::macros::import::Option::None,
        }
    };
}

pub(crate) use const_option_map;

#[cfg(feature = "serde")]
macro_rules! deserialize_str {
    ($deserializer: expr) => {{
        type Slice<'s> = &'s str;

        Slice::deserialize($deserializer)
    }};
}

#[cfg(feature = "serde")]
pub(crate) use deserialize_str;

macro_rules! quick_error {
    ($condition: expr => $error: expr) => {
        if $condition {
            return $crate::macros::import::Result::Err($error);
        }
    };
}

pub(crate) use quick_error;

macro_rules! errors {
    (
        Type = $type: ty,
        Hack = $hack: tt,
        $(
            $name: ident => $method: ident (
                $(
                    $variable_name: ident $(=> $prepare: ident)?
                ),*
                $(,)?
            )
        ),*
        $(,)?
    ) => {
        $(
            macro_rules! $name {
                (
                    $(
                        $hack $variable_name: expr
                    ),*
                ) => {
                    <$type>::$method(
                        $(
                            $hack $variable_name$(.$prepare())?
                        ),*
                    )
                }
            }
        )*
    };
}

pub(crate) use errors;
