use std::{
    any::{Any, TypeId},
    borrow::Cow,
    collections::HashMap,
    error::Error,
    pin::Pin,
};

use sqlx::PgConnection;

pub mod time_source;
pub mod user;

pub async fn default_fixture(conn: &mut PgConnection) -> Result<(), FixtureError> {
    run_fixtures!(conn, [user::fixture, time_source::fixture,]).await?;

    Ok(())
}

/// An error that can occur during fixture loading
#[derive(Debug)]
pub enum FixtureError {
    Database(sqlx::Error),
    MissingContextValue {
        type_name: &'static str,
        name: String,
    },
    Other(eyre::Report),
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixtureError::Database(_) => write!(f, "Database error"),
            FixtureError::MissingContextValue { type_name, name } => {
                write!(
                    f,
                    "Missing context value of type '{}' with name '{}'",
                    type_name, name
                )
            }
            FixtureError::Other(_) => write!(f, "An application error occured"),
        }
    }
}

impl Error for FixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FixtureError::Database(e) => Some(e),
            FixtureError::MissingContextValue { .. } => None,
            FixtureError::Other(e) => Some(&**e),
        }
    }
}

impl From<sqlx::Error> for FixtureError {
    fn from(e: sqlx::Error) -> Self {
        FixtureError::Database(e)
    }
}

impl From<eyre::Report> for FixtureError {
    fn from(e: eyre::Report) -> Self {
        FixtureError::Other(e)
    }
}

/// A context object that can be passed between fixture steps, allowing them to share data.
///
/// Values are stored in the context based on their type and an optional name,
/// allowing multiple values of the same type to be stored and retrieved by name.
pub struct FixtureContext {
    data: HashMap<(TypeId, Cow<'static, str>), Box<dyn Any + Send + Sync>>,
}

impl FixtureContext {
    pub fn new() -> Self {
        FixtureContext {
            data: HashMap::new(),
        }
    }

    /// Store a value of type `T` in the context with a name, and return the context for chaining.
    pub fn with<T: Any + Send + Sync>(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: T,
    ) -> Self {
        self.set(name, value);
        self
    }

    /// Remove a value of type `T` from the context with a name, and return the context for chaining.
    pub fn without<T: Any + Send + Sync>(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.remove::<T>(name);
        self
    }

    /// Store a value of type `T` in the context with a name.
    pub fn set<T: Any + Send + Sync>(&mut self, name: impl Into<Cow<'static, str>>, value: T) {
        // Store the value in the context
        self.data
            .insert((TypeId::of::<T>(), name.into()), Box::new(value));
    }

    /// Retrieve a reference to a value of type `T` from the context with a name.
    pub fn get<'a, T: Any + Send + Sync>(&'a self, name: &'a str) -> Result<&'a T, FixtureError> {
        self.data
            .get(&(TypeId::of::<T>(), Cow::Borrowed(name)))
            .and_then(|value| value.downcast_ref())
            .ok_or_else(|| FixtureError::MissingContextValue {
                type_name: std::any::type_name::<T>(),
                name: name.to_string(),
            })
    }

    /// Retrieve a copy of a value of type `T` from the context with a name.
    pub fn get_copy<T: Any + Send + Sync + Copy>(&self, name: &str) -> Result<T, FixtureError> {
        self.get(name).copied()
    }

    /// Retrieve a copy of a value of type `T` from the context with a name, or return a default value if it doesn't exist.
    pub fn get_copy_or<T: Any + Send + Sync + Copy>(&self, name: &str, else_value: T) -> T {
        self.get(name).copied().unwrap_or(else_value)
    }

    /// Retrieve a clone of a value of type `T` from the context with a name.
    pub fn get_clone<T: Any + Send + Sync + Clone>(&self, name: &str) -> Result<T, FixtureError> {
        self.get(name).cloned()
    }

    /// Retrieve a clone of a value of type `T` from the context with a name, or return a default value if it doesn't exist.
    pub fn get_clone_or_else<T: Any + Send + Sync + Clone>(
        &self,
        name: &str,
        else_fn: impl FnOnce() -> T,
    ) -> T {
        self.get(name).cloned().unwrap_or_else(|_| else_fn())
    }

    /// Remove a value of type `T` from the context with a name.
    pub fn remove<T: Any + Send + Sync>(&mut self, name: impl Into<Cow<'static, str>>) {
        let name = name.into();
        self.data.remove(&(TypeId::of::<T>(), name));
    }

    /// Take a value of type `T` from the context with a name, removing it from the context and returning it if it exists.
    pub fn take<T: Any + Send + Sync>(
        &mut self,
        name: impl Into<Cow<'static, str>>,
    ) -> Result<Option<T>, FixtureError> {
        let name = name.into();
        let key = (TypeId::of::<T>(), name);

        self.data
            .remove(&key)
            .map(|value| value.downcast::<T>().map(|boxed| *boxed))
            .transpose()
            .map_err(|_| FixtureError::MissingContextValue {
                type_name: std::any::type_name::<T>(),
                name: key.1.to_string(),
            })
    }

    /// Merge another `FixtureContext` into this one, with values from the other context taking precedence in case of conflicts.
    pub fn join(mut self, other: Self) -> Self {
        self.data.extend(other.data);
        self
    }
}

type FixtureFn = for<'a> fn(
    &'a mut PgConnection,
    FixtureContext,
) -> Pin<
    Box<dyn Future<Output = Result<FixtureContext, FixtureError>> + Send + 'a>,
>;

pub struct FixtureRunner {
    fixtures: Vec<FixtureFn>,
}

impl FixtureRunner {
    pub fn new() -> Self {
        FixtureRunner {
            fixtures: Vec::new(),
        }
    }

    fn step(mut self, f: FixtureFn) -> Self {
        self.fixtures.push(f);
        self
    }

    async fn run(self, conn: &mut PgConnection) -> Result<FixtureContext, FixtureError> {
        let mut context = FixtureContext::new();
        for fixture in self.fixtures {
            context = fixture(conn, context).await?;
        }

        Ok(context)
    }
}

#[macro_export]
macro_rules! fixture_fn {
    ($fn_name:expr) => {
        |conn: &mut PgConnection, context: FixtureContext| Box::pin($fn_name(conn, context))
    };
}
pub use fixture_fn;

#[macro_export]
macro_rules! run_fixtures {
    ($conn:expr, [$($fixture:expr),* $(,)?]) => {
        FixtureRunner::new()
            $(.step(fixture_fn!($fixture)))*
            .run($conn)
    };
}
pub use run_fixtures;
