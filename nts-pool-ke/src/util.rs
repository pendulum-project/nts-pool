use rustls::pki_types::pem::PemObject;

pub fn load_certificates(
    path: impl AsRef<std::path::Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    rustls::pki_types::CertificateDer::pem_file_iter(path)?.collect()
}

/// Join handle that automatically aborts the task when dropped.
///
/// Can be used to automatically stop update tasks once they are no longer needed.
pub struct AbortingJoinHandle<T>(tokio::task::JoinHandle<T>);

impl<T> From<tokio::task::JoinHandle<T>> for AbortingJoinHandle<T> {
    fn from(value: tokio::task::JoinHandle<T>) -> Self {
        AbortingJoinHandle(value)
    }
}

impl<T> std::ops::Deref for AbortingJoinHandle<T> {
    type Target = tokio::task::JoinHandle<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for AbortingJoinHandle<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Drop for AbortingJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
