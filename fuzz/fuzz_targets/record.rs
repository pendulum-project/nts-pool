#![no_main]

use std::{
    pin::pin,
    task::{Context, Waker},
};

use libfuzzer_sys::fuzz_target;
use pool_nts::{BufferBorrowingReader, NtsRecord};

fuzz_target!(|data: &[u8]| {
    let mut buf1 = [0u8; 4096];
    match pin!(NtsRecord::parse(&mut BufferBorrowingReader::new(
        data, &mut buf1
    )))
    .poll(&mut Context::from_waker(Waker::noop()))
    {
        std::task::Poll::Ready(Ok(record)) => {
            let mut out1 = vec![];
            assert!(matches!(
                pin!(record.serialize(&mut out1)).poll(&mut Context::from_waker(Waker::noop())),
                std::task::Poll::Ready(Ok(_))
            ));
            let mut buf2 = [0u8; 4096];
            let std::task::Poll::Ready(Ok(record2)) = pin!(NtsRecord::parse(
                &mut BufferBorrowingReader::new(out1.as_slice(), &mut buf2)
            ))
            .poll(&mut Context::from_waker(Waker::noop())) else {
                panic!("Unexpected stall during parsing");
            };
            let mut out2 = vec![];
            assert!(matches!(
                pin!(record2.serialize(&mut out2)).poll(&mut Context::from_waker(Waker::noop())),
                std::task::Poll::Ready(Ok(_))
            ));
            assert_eq!(out1, out2);
        }
        std::task::Poll::Ready(_) => {}
        std::task::Poll::Pending => panic!("Unexpected stall during parsing"),
    }
});
