
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

pub fn pkcs7_pad(bytes: &[u8], blocklen: usize) -> Result<Vec<u8>, String> {
    if blocklen > u8::MAX as usize {
        return Err(format!("blocklen {} is more than max byte value", blocklen));
    }
    let padlen = if bytes.len() < blocklen {
        blocklen - bytes.len()
    } else {
        blocklen - (bytes.len() % blocklen)
    };
    let mut result = bytes.to_vec();
    let mut pad = match padlen {
        0 => vec![blocklen as u8; blocklen],
        d => vec![d as u8; d],
    };
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
