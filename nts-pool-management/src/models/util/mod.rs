pub mod port;

macro_rules! uuid {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            Eq,
            Ord,
            PartialEq,
            PartialOrd,
            sqlx::Type,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[repr(transparent)]
        #[sqlx(transparent)]
        pub struct $name(uuid::Uuid);

        impl From<uuid::Uuid> for $name {
            fn from(uuid: uuid::Uuid) -> Self {
                Self(uuid)
            }
        }

        impl std::ops::Deref for $name {
            type Target = uuid::Uuid;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        #[cfg(test)]
        #[allow(unused)]
        impl $name {
            pub(crate) fn new_test() -> Self {
                Self(uuid::Uuid::new_v4())
            }
        }

        impl $name {
            /// Get the inner `Uuid` value. Should only be used when necessary.
            pub fn get_inner_uuid(self) -> uuid::Uuid {
                self.0
            }
        }
    };
}

pub(crate) use uuid;
