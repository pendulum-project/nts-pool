use std::sync::{Arc, atomic::AtomicU64};

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

#[derive(Debug, Clone)]
pub struct ArrayDeque<const N: usize, T> {
    data: [Option<T>; N],
    read: usize,
    write: usize,
}

impl<T, const N: usize> ArrayDeque<N, T> {
    #[must_use]
    pub fn new() -> Self {
        ArrayDeque {
            data: core::array::from_fn(|_| None),
            read: 0,
            write: 0,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data[self.read].is_none()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.read == self.write && self.data[self.read].is_some()
    }

    #[must_use]
    pub fn size(&self) -> usize {
        if self.read < self.write {
            self.write - self.read
        } else if self.read == self.write {
            if self.data[self.read].is_some() { N } else { 0 }
        } else {
            self.write + N - self.read
        }
    }

    #[must_use]
    pub fn pop(&mut self) -> Option<T> {
        if let Some(el) = self.data[self.read].take() {
            self.read = (self.read + 1) % N;
            Some(el)
        } else {
            None
        }
    }

    #[must_use]
    pub fn try_push(&mut self, el: T) -> Option<T> {
        if self.data[self.write].is_none() {
            self.data[self.write] = Some(el);
            self.write = (self.write + 1) % N;
            None
        } else {
            Some(el)
        }
    }
}

#[derive(Default, Debug, Clone)]
pub(crate) struct ActiveCounter {
    counter: Arc<AtomicU64>,
}

impl ActiveCounter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get_active_token(&self) -> ActiveCounterToken {
        self.counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ActiveCounterToken {
            counter: self.counter.clone(),
        }
    }

    pub(crate) fn current_count(&self) -> u64 {
        self.counter.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct ActiveCounterToken {
    counter: Arc<AtomicU64>,
}

impl Drop for ActiveCounterToken {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}
