// Challenge 10
//
// Implement CBC mode
//
// CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite
// the fact that a block cipher natively only transforms individual blocks.
//
// In CBC mode, each ciphertext block is added to the next plaintext block before the next call to
// the cipher core.
//
// The first plaintext block, which has no associated previous ciphertext block, is added to a
// "fake 0th ciphertext block" called the initialization vector, or IV.
//
// Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt
// instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR
// function from the previous exercise to combine them.
//
// File 10.txt is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an
// IV of all ASCII 0 (\x00\x00\x00 &c)

extern crate data_encoding;
extern crate crypto;

use std::borrow::BorrowMut;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use data_encoding::base64;
use self::crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};
use self::crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

fn bytewise_xor(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    assert_eq!(left.len(), right.len());
    left
        .iter()
        .zip(right.iter())
        .map(|(&l, &r)| l^r)
        .collect::<Vec<u8>>()
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(key);
    let mut iv = iv.to_vec();
    assert!(iv.len() > 0);
    let mut output: Vec<u8> = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks(16) {
        let mut result = vec![0; 16];
        encryptor.encrypt_block(bytewise_xor(block.to_vec(), iv).as_slice(), &mut result);
        iv = result.clone();
        output.append(&mut result);
    }
    output
}

pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let decryptor = AesSafe128Decryptor::new(key);
    let mut iv = iv.to_vec();
    let mut output: Vec<u8> = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks(16) {
        let mut result = vec![0; 16];
        decryptor.decrypt_block(block, &mut result);
        output.append(bytewise_xor(result, iv).borrow_mut());
        iv = block.to_vec();
    }
    output
}

pub fn cbc_decrypt_file(filename: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let decoded = base64::decode(
            BufReader::new(File::open(filename).unwrap())
            .lines()
            .fold(String::new(), |acc, l| acc + &(l.unwrap()))
            .as_bytes()
        ).unwrap();
    cbc_decrypt(decoded.as_slice(), key, iv)

}
