use std::ffi::{CStr};
use std::os::raw::c_char;
use once_cell::sync::OnceCell;

static RT: OnceCell<tokio::runtime::Runtime> = OnceCell::new();

fn rt() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

#[no_mangle]
pub extern "C" fn gmf_run_once(api_ptr: *const c_char, api_key_ptr: *const c_char) -> bool {
    if api_ptr.is_null() || api_key_ptr.is_null() {
        return false;
    }
    let api = unsafe { CStr::from_ptr(api_ptr) }.to_string_lossy().to_string();
    let api_key = unsafe { CStr::from_ptr(api_key_ptr) }.to_string_lossy().to_string();

    let fut = async move {
        gmf_core::lease_execute_report_once_mobile(&api, &api_key).await
    };

    match rt().block_on(fut) {
        Ok(_) => true,
        Err(_) => false,
    }
}
