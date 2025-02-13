//! Various macros used by this crate.

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
