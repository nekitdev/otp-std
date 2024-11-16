/// Constantly asserts the given condition.
macro_rules! const_assert {
    ($condition: expr) => {
        const _: () = assert!($condition);
    };
}

pub(crate) use const_assert;
