use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

use subtle_encoding::{base64};

#[no_mangle]
pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/*
fn main() {
    let cstrdata = CString::new("Hello world! These are more words how does it do that?").unwrap();
    let cstrkey = CString::new("O8KAuODxb7PRdxXlgBVxgdJY8KpGK33VAq1Kp927B7s=").unwrap();
    let cstriv = CString::new("ZP4rO1AvfQLKAWfidfRtWA==").unwrap();

    let ptr = encrypt_cbc(cstrdata.as_ptr(), cstrkey.as_ptr(), cstriv.as_ptr());

    let encrypted = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };

    println!("{}", encrypted);
    //println!("{}", encrypt_cbc(cstrdata, cstrkey, cstriv));
}
*/

#[no_mangle]
pub extern "C" fn encrypt_cbc(data: *const c_char, key: *const c_char, iv: *const c_char) -> *const c_char {
    let data_str = unsafe { CStr::from_ptr(data) };
    let key_str = unsafe { CStr::from_ptr(key) };
    let iv_str = unsafe { CStr::from_ptr(iv) };

    let iv_vec = base64::decode(iv_str.to_bytes()).unwrap();
    let data_vec = data_str.to_bytes();
    let key_vec = base64::decode(key_str.to_bytes()).unwrap();

    let len = data_vec.len();
    let mut new_data_vec: Vec<u8> = vec![0; len + 32 - (len % 32)];
    let slice = new_data_vec.as_mut_slice();
    slice[..len].copy_from_slice(data_vec);

    let cipher = Aes256Cbc::new_var(key_vec.as_slice(), iv_vec.as_slice()).unwrap();
    let cipher_txt = cipher.encrypt(slice, len);
    let cipher_str_txt = String::from_utf8(base64::encode(cipher_txt.unwrap().to_vec())).unwrap();

    let cstr_cipher_txt = CString::new(cipher_str_txt).unwrap();
    let ptr = cstr_cipher_txt.as_ptr();
    std::mem::forget(cstr_cipher_txt);
    ptr
}
