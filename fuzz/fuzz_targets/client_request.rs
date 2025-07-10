#![no_main]

use std::{
    pin::pin,
    task::{Context, Waker},
};

use libfuzzer_sys::fuzz_target;
use nts_pool_ke::nts::ClientRequest;

fuzz_target!(|data: &[u8]| {
    match pin!(ClientRequest::parse(data)).poll(&mut Context::from_waker(Waker::noop())) {
        std::task::Poll::Ready(_) => {}
        std::task::Poll::Pending => panic!("Unexpected failure to complete parsing"),
    }
});
