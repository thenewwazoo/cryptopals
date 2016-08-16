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
use self::crypto::aes::{self, KeySize};
use self::crypto::blockmodes::NoPadding;
use self::crypto::buffer::{self, WriteBuffer, ReadBuffer, BufferResult};
use self::crypto::symmetriccipher;

pub fn decrypt_file(filename: &str, key: &[u8]) -> Vec<u8> {
    let ciphertext = base64::decode(
        BufReader::new(File::open(filename).unwrap())
        .lines()
        .fold(String::new(), |acc, l| acc + &(l.unwrap()))
        .as_bytes()
        ).unwrap();

    decrypt(&ciphertext[..], key).unwrap()
}

// why the hell do I have to juggle buffers to do this? why the hell are all the BlockEngine structs private?
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor(KeySize::KeySize128, key, NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
