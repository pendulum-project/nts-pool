use std::{mem::take, pin::Pin};

use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

pub struct BufferBorrowingReader<'a, T> {
    buf: &'a mut [u8],
    fill: usize,
    reader: T,
}

impl<'a, T: AsyncRead + Unpin> BufferBorrowingReader<'a, T> {
    pub fn new(reader: T, buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            fill: 0,
            reader,
        }
    }

    pub async fn read_bufref(&mut self, len: usize) -> std::io::Result<&'a [u8]> {
        while self.fill < len {
            match self.reader.read(&mut self.buf[self.fill..]).await {
                Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.fill += n,
                Err(e) => return Err(e),
            }
        }

        let (result, remainder) = take(&mut self.buf).split_at_mut(len);
        self.buf = remainder;
        self.fill -= len;
        Ok(result)
    }
}

impl<'a> From<&'a mut [u8]> for BufferBorrowingReader<'a, &[u8]> {
    fn from(value: &'a mut [u8]) -> Self {
        BufferBorrowingReader {
            fill: value.len(),
            buf: value,
            reader: &[],
        }
    }
}

impl<'a, T: AsyncRead + Unpin> AsyncRead for BufferBorrowingReader<'a, T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.fill == 0 {
            let mut bufread = ReadBuf::new(this.buf);
            match Pin::new(&mut this.reader).poll_read(cx, &mut bufread) {
                std::task::Poll::Ready(Ok(_)) => this.fill += bufread.filled().len(),
                v => return v,
            }
        }
        let len = this.fill.min(buf.remaining());
        buf.put_slice(&this.buf[..len]);
        let temp = take(&mut this.buf);
        this.buf = &mut temp[len..];
        this.fill -= len;
        std::task::Poll::Ready(Ok(()))
    }
}

pub fn load_certificates(
    path: impl AsRef<std::path::Path>,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    rustls::pki_types::CertificateDer::pem_file_iter(path)?.collect()
}
