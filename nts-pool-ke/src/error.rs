use crate::nts::NtsError;

#[derive(Debug)]
pub enum PoolError {
    NtsError(NtsError),
    IO(std::io::Error),
    Rustls(rustls::Error),
    Timeout,
}

impl From<NtsError> for PoolError {
    fn from(value: NtsError) -> Self {
        PoolError::NtsError(value)
    }
}

impl From<std::io::Error> for PoolError {
    fn from(value: std::io::Error) -> Self {
        PoolError::IO(value)
    }
}

impl From<rustls::Error> for PoolError {
    fn from(value: rustls::Error) -> Self {
        PoolError::Rustls(value)
    }
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtsError(e) => e.fmt(f),
            Self::IO(e) => e.fmt(f),
            Self::Rustls(e) => e.fmt(f),
            Self::Timeout => f.write_str("Timeout occured"),
        }
    }
}

impl std::error::Error for PoolError {}
