use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use gmf_agent_core::{register_device, tick};

fn cstr(s: *const c_char) -> String {
    if s.is_null() { return "".to_string(); }
    unsafe { CStr::from_ptr(s).to_string_lossy().to_string() }
}

#[no_mangle]
pub extern "C" fn gmf_register_device(api: *const c_char, device_id: *const c_char, platform: *const c_char, topics: *const c_char, ram_mb: i64, disk_mb: i64) -> c_int {
    let api = cstr(api);
    let device_id = cstr(device_id);
    let platform = cstr(platform);
    let topics = cstr(topics);
    match register_device(&api, &device_id, &platform, &topics, ram_mb, disk_mb) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn gmf_tick(api: *const c_char, device_id: *const c_char, platform: *const c_char, topics: *const c_char) -> c_int {
    let api = cstr(api);
    let device_id = cstr(device_id);
    let platform = cstr(platform);
    let topics = cstr(topics);
    match tick(&api, &device_id, &platform, &topics) {
        Ok(r) => {
            // return codes: 0=ran no job, 2=accepted, 3=rejected
            if !r.had_job { 0 } else if r.accepted { 2 } else { 3 }
        }
        Err(_) => 1, // error
    }
}

/// optional: return a static header string for quick integration
#[no_mangle]
pub extern "C" fn gmf_mobile_ffi_header() -> *const c_char {
    static HDR: &str =
"// gmf_mobile_ffi.h\n\
#pragma once\n\
#include <stdint.h>\n\
#ifdef __cplusplus\nextern \"C\" {\n#endif\n\
int gmf_register_device(const char* api, const char* device_id, const char* platform, const char* topics, int64_t ram_mb, int64_t disk_mb);\n\
int gmf_tick(const char* api, const char* device_id, const char* platform, const char* topics);\n\
const char* gmf_mobile_ffi_header();\n\
#ifdef __cplusplus\n}\n#endif\n";
    HDR.as_ptr() as *const c_char
}
