use crate::transform::XorWith;
use aes::Aes128;
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Ecb};

/// Decrypt `ciphertext` using `key` in CBC mode.
pub fn cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    let mut iv = vec![0u8; 16];

    let mut cleartext = Vec::new();
    for block in ciphertext.chunks(16) {
        type Aes128Ecb = Ecb<Aes128, ZeroPadding>;

        let cipher = Aes128Ecb::new_var(key, Default::default()).unwrap();

        let clear_block = cipher.decrypt_vec(&block).map_err(|_| ())?;
        let res = clear_block.xor_with(&iv);
        cleartext.extend_from_slice(&res);
        iv = block.to_vec();
    }

    Ok(cleartext)
}
