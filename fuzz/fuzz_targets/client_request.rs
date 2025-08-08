#![no_main]

use std::{
    pin::pin,
    task::{Context, Waker},
};

use libfuzzer_sys::fuzz_target;
use nts_pool_ke::{nts::ClientRequest, BufferBorrowingReader};

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 4096];
    match pin!(ClientRequest::parse(&mut BufferBorrowingReader::new(
        data, &mut buf
    )))
    .poll(&mut Context::from_waker(Waker::noop()))
    {
        std::task::Poll::Ready(_) => {}
        std::task::Poll::Pending => panic!("Unexpected failure to complete parsing"),
    }
});
