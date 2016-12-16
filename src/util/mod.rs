
pub mod base64;
pub mod bit_manip;
pub mod cipher;
pub mod hex;
pub mod oracles;
pub mod stat;
pub mod encryption;

extern crate rand;

use self::rand::Rng;

use std::u8;

pub fn pkcs7_pad_block(block: &[u8], len: usize) -> Result<Vec<u8>, String> {
    if block.len() > len || len > u8::MAX as usize {
        return Err("bad len value".to_string());
    }
    let mut result = block.to_vec();
    let diff = len - block.len();
    let mut pad = vec![diff as u8; diff];
    result.append(&mut pad);
    Ok(result)
}

pub fn generate_key(size: usize) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    for _ in 0..size {
        output.push(rng.gen());
    }
    output.clone()
}
