mod core_jobs;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn core_run(input_json: &str) -> String {
    let out = core_jobs::run_job_json(input_json);
    serde_json::to_string(&out).unwrap_or_else(|e| format!(r#"{{"kind":"gmf_error","message":"serialize_error:{e}"}}"#))
}

#[no_mangle]
pub extern "C" fn gmf_run_job(input_json: *const c_char) -> *mut c_char {
    if input_json.is_null() {
        return CString::new(r#"{"kind":"gmf_error","message":"null_input"}"#).unwrap().into_raw();
    }
    let cstr = unsafe { CStr::from_ptr(input_json) };
    let s = cstr.to_string_lossy();
    let out = core_run(&s);
    CString::new(out).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn gmf_free(p: *mut std::ffi::c_void) {
    if p.is_null() { return; }
    unsafe { let _ = CString::from_raw(p as *mut c_char); }
}

// compatibility aliases
#[no_mangle] pub extern "C" fn gmf_ios_run_job(input_json: *const c_char) -> *mut c_char { gmf_run_job(input_json) }
#[no_mangle] pub extern "C" fn gmf_ios_free(p: *mut std::ffi::c_void) { gmf_free(p) }
#[no_mangle] pub extern "C" fn gmf_android_run_job(input_json: *const c_char) -> *mut c_char { gmf_run_job(input_json) }
#[no_mangle] pub extern "C" fn gmf_android_free(p: *mut std::ffi::c_void) { gmf_free(p) }
