// Challenge 7
//
// AES in ECB mode
//
// The Base64-encoded content in 7.txt has been encrypted via AES-128 in ECB mode under the key
//
// "YELLOW SUBMARINE".
//
// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because
// it's exactly 16 bytes long, and now you do too).
//
// Decrypt it. You know the key, after all.
//
// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

extern crate data_encoding;
extern crate crypto;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use self::data_encoding::base64;
use self::crypto::aessafe::AesSafe128Decryptor;
use self::crypto::symmetriccipher::BlockDecryptor;

pub fn decrypt_file(filename: &str, key: &[u8]) -> Vec<u8> {
    let decryptor = AesSafe128Decryptor::new(key);

    base64::decode(
            BufReader::new(File::open(filename).unwrap())
            .lines()
            .fold(String::new(), |acc, l| acc + &(l.unwrap()))
            .as_bytes()
        ).unwrap()
        .chunks(16)
        .flat_map(|c| {
            let mut output = vec![0; 16];
            decryptor.decrypt_block(c, output.as_mut_slice());
            output
        })
        .collect::<Vec<u8>>()
}
