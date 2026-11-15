use std::ffi::{c_char, CStr, CString};

// The caller passes a NUL-terminated UTF-8 JSON string. The returned string
// belongs to Rust and must be released with attest_link_free after reading it.
#[no_mangle]
pub unsafe extern "C" fn attest_link_verify(input: *const c_char) -> *mut c_char {
    let json = match CStr::from_ptr(input).to_str() {
        Ok(input) => attest_link_rust::wasm::verify_json(input),
        Err(error) => serde_json::json!({ "error": error.to_string() }).to_string(),
    };
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn attest_link_free(output: *mut c_char) {
    drop(CString::from_raw(output));
}

fn main() {}
