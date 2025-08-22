pub mod auth;
pub mod config;
pub mod context;
pub mod email;
pub mod error;

use std::convert::Infallible;

/// Helper trait to unwrap a Result where the Error is Infallible
pub trait InfallibleUnwrap<T> {
    /// Remove the Result, always return the value T (because the Error case is impossible to reach).
    fn infallible_unwrap(self) -> T;
}

impl<T> InfallibleUnwrap<T> for Result<T, Infallible> {
    fn infallible_unwrap(self) -> T {
        match self {
            Ok(v) => v,
            Err(e) => match e {}, // unreachable
        }
    }
}
