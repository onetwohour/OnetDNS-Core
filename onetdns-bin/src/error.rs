//! Error context for startup paths: without the file or step, a message alone does not say where it
//! failed.

pub type BoxResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub trait Context<T> {
    /// The message is built only on failure.
    fn with_context<C: std::fmt::Display, F: FnOnce() -> C>(self, f: F) -> BoxResult<T>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Context<T> for std::result::Result<T, E> {
    fn with_context<C: std::fmt::Display, F: FnOnce() -> C>(self, f: F) -> BoxResult<T> {
        self.map_err(|e| format!("{}: {e}", f()).into())
    }
}

#[macro_export]
macro_rules! anyhow {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        ::std::boxed::Box::<dyn ::std::error::Error + Send + Sync>::from(format!($fmt $(, $arg)*))
    };
    ($e:expr) => {
        ::std::boxed::Box::<dyn ::std::error::Error + Send + Sync>::from(format!("{}", $e))
    };
}

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return ::std::result::Result::Err($crate::anyhow!($($t)*))
    };
}
