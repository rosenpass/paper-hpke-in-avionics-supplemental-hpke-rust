#[derive(Debug)]
pub struct OqsError;

pub fn call_oqs<F: FnOnce() ->  oqs_sys::common::OQS_STATUS>(f: F) -> Result<(), OqsError> {
    match f() {
        oqs_sys::common::OQS_STATUS::OQS_SUCCESS => Ok(()),
        _ => Err(OqsError),
    }
}
