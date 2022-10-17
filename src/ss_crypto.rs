//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Contains encryption and decryption using aes.
// Could also contain setting aes key

use crate::error::{Result, Error};

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    let mut ctx = CipherCtx::new().expect("cipher creation should not fail");
    ctx.encrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(iv))
        .expect("cipher init should not fail");

    let mut output = vec![];
    ctx.cipher_update_vec(data, &mut output)
        .expect("cipher update should not fail");
    ctx.cipher_final_vec(&mut output)
        .expect("cipher final should not fail");
    output
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    let mut ctx = CipherCtx::new().expect("cipher creation should not fail");
    ctx.decrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(iv))
        .expect("cipher init should not fail");

    let mut output = vec![];
    ctx.cipher_update_vec(encrypted_data, &mut output)
        .map_err(|_| Error::Crypto("message decryption failed".to_string()))?;
    ctx.cipher_final_vec(&mut output)
        .map_err(|_| Error::Crypto("message decryption failed".to_string()))?;
    Ok(output)
}
