use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn gmf_free_c_string(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { drop(CString::from_raw(ptr)); }
}

#[no_mangle]
pub extern "C" fn gmf_generate_device_identity_json() -> *mut c_char {
    match gmf_core::load_or_create_device_identity() {
        Ok(id) => {
            match serde_json::to_string(&id) {
                Ok(s) => CString::new(s).unwrap().into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn gmf_set_device_identity_json(json_ptr: *const c_char) -> bool {
    if json_ptr.is_null() { return false; }
    let cstr = unsafe { CStr::from_ptr(json_ptr) };
    match cstr.to_str() {
        Ok(s) => gmf_core::set_device_identity_override_json(s).is_ok(),
        Err(_) => false,
    }
}
