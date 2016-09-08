// Challenge 11
//
// An ECB/CBC detection oracle
//
// Now that you have ECB and CBC working:
//
// Write a function to generate a random AES key; that's just 16 random bytes.
//
// Write a function that encrypts data under an unknown key --- that is, a function that generates
// a random key and encrypts under it.
//
// The function should look like:
//
// encryption_oracle(your-input)
// => [MEANINGLESS JIBBER JABBER]
//
// Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
// and 5-10 bytes after the plaintext.
//
// Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
// (just use random IVs each time for CBC). Use rand(2) to decide which to use.
//
// Detect the block cipher mode the function is using each time. You should end up with a piece of
// code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is
// happening.

extern crate rand;
extern crate crypto;

use self::rand::Rng;
use self::crypto::aessafe::AesSafe128Encryptor;
use self::crypto::symmetriccipher::BlockEncryptor;

use challenge8::detect_ecb;
use challenge10;

pub fn ecb_oracle() {
    for _ in 0..100 {
        let (ciphertext, _key, is_cbc) =
            encryption_butterfly("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
        if is_cbc == detect_ecb(&ciphertext) {
            panic!("you suck!");
        }
    }
}

fn generate_key(size: usize) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(size);
    let mut rng = rand::thread_rng();

    for _ in 0..size {
        output.push(rng.gen());
    }
    output.clone()
}

pub fn encryption_butterfly(plaintext: &[u8]) -> (Vec<u8>, Vec<u8>, bool) {
    let key = generate_key(16);
    let mut rng = rand::thread_rng();
    let padding = generate_key( (rng.gen::<usize>() % 6) + 5);
    let padlen = 16 - (plaintext.len() + 2*padding.len()) % 16;
    let mut padded_plaintext: Vec<u8> = Vec::with_capacity(plaintext.len() + 2*padding.len());
    padded_plaintext.extend(padding.iter());
    padded_plaintext.extend(plaintext.iter());
    padded_plaintext.extend(padding.iter());
    padded_plaintext.extend(vec![0 as u8; padlen]);

    if rng.gen() {
        // cbc
        let iv = generate_key(16);
        (challenge10::cbc_encrypt(&padded_plaintext, &key, &iv), key, true)
    } else {
        // ecb
        (ecb_encrypt(&padded_plaintext, &key), key, false)
    }
}

pub fn ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let encryptor = AesSafe128Encryptor::new(key);
    let mut output: Vec<u8> = Vec::with_capacity(plaintext.len());

    for block in plaintext.chunks(16) {
        let mut result = vec![0; 16];
        encryptor.encrypt_block(block, &mut result);
        output.append(&mut result);
    }
    output
}
