use std::ops::{Deref, DerefMut};

use serde::Deserialize;
use sqlx::{
    Decode, Encode, Postgres, Type,
    postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef},
};

#[derive(Debug, Deserialize, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Port(u16);

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Port(port)
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.0
    }
}

impl Deref for Port {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Port {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Type<Postgres> for Port {
    fn type_info() -> PgTypeInfo {
        <i32 as Type<Postgres>>::type_info()
    }
}

impl<'r> Decode<'r, Postgres> for Port {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let int_value: i32 = Decode::<Postgres>::decode(value)?;
        Ok(Port(u16::try_from(int_value)?))
    }
}

impl<'q> Encode<'q, Postgres> for Port {
    fn produces(&self) -> Option<PgTypeInfo> {
        Some(<i32 as Type<Postgres>>::type_info())
    }

    fn size_hint(&self) -> usize {
        4
    }

    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        Encode::<Postgres>::encode_by_ref(&(self.0 as i32), buf)
    }
}
