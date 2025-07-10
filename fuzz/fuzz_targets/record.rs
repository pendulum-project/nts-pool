#![no_main]

use std::{
    pin::pin,
    task::{Context, Waker},
};

use libfuzzer_sys::fuzz_target;
use nts_pool_ke::nts::NtsRecord;

fuzz_target!(|data: &[u8]| {
    match pin!(NtsRecord::parse(data)).poll(&mut Context::from_waker(Waker::noop())) {
        std::task::Poll::Ready(Ok(record)) => {
            let mut out1 = vec![];
            assert!(matches!(
                pin!(record.serialize(&mut out1)).poll(&mut Context::from_waker(Waker::noop())),
                std::task::Poll::Ready(Ok(_))
            ));
            let std::task::Poll::Ready(Ok(record2)) = pin!(NtsRecord::parse(out1.as_slice()))
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
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
