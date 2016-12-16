
extern crate crypto;

use self::crypto::aessafe::{AesSafe128Decryptor, AesSafe128Encryptor};
use self::crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};

use std::borrow::BorrowMut;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;

use util::bit_manip::bytewise_xor;
use util::base64::FromBase64;
use util::pkcs7_pad_block;

#[derive(Debug,PartialEq)]
pub enum EncryptionMode
{
    AesEcb,
    AesCbc
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(key);
    let mut iv = iv.to_vec();
    assert!(iv.len() > 0);
    let mut output: Vec<u8> = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks(16) {
        let mut result = vec![0; 16];
        let block = pkcs7_pad_block(block, 16).unwrap();
        encryptor.encrypt_block(bytewise_xor(&block, &iv).as_slice(), &mut result);
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
        output.append(bytewise_xor(&result, &iv).borrow_mut());
        iv = block.to_vec();
    }
    output
}


pub fn cbc_decrypt_file(filename: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let decoded = BufReader::new(
            File::open(filename).unwrap()
        )
        .lines()
        .fold(String::new(), |acc, l| acc + &(l.unwrap()))
        .from_base64();
    cbc_decrypt(&decoded, key, iv)
}


pub fn ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let key = pkcs7_pad_block(key, 16).unwrap();
    let encryptor = AesSafe128Encryptor::new(&key);
    let mut output: Vec<u8> = Vec::with_capacity(plaintext.len());

    for block in plaintext.chunks(16) {
        let mut result = vec![0; 16];
        let block = pkcs7_pad_block(block, 16).unwrap();
        encryptor.encrypt_block(&block, &mut result);
        output.append(&mut result);
    }
    output
}
