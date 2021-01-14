use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

use subtle_encoding::{base64};

#[no_mangle]
pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[no_mangle]
pub extern "C" fn encrypt_cbc(data: *const c_char, key: *const c_char, iv: *const c_char) -> *const c_char {
    let data_str = unsafe { CStr::from_ptr(data) };
    let key_str = unsafe { CStr::from_ptr(key) };
    let iv_str = unsafe { CStr::from_ptr(iv) };

    let iv_vec = base64::decode(iv_str.to_bytes()).unwrap();
    let data_slice = base64::decode(data_str.to_bytes()).unwrap();
    let key_vec = base64::decode(key_str.to_bytes()).unwrap();

    let cipher = Aes256Cbc::new_var(key_vec.as_slice(), iv_vec.as_slice()).unwrap();
    let cipher_txt = cipher.encrypt_vec(data_slice.as_slice());
    let cipher_str_txt = String::from_utf8(base64::encode(cipher_txt)).unwrap();

    let cstr_cipher_txt = CString::new(cipher_str_txt).unwrap();
    let ptr = cstr_cipher_txt.as_ptr();
    std::mem::forget(cstr_cipher_txt);
    ptr
}