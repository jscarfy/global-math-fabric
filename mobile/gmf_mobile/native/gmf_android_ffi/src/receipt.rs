use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn gmf_take_last_receipt_json() -> *mut c_char {
    match gmf_core::take_last_receipt_json() {
        Some(s) => CString::new(s).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}
