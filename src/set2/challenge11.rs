/// Challenge 11
///
/// An ECB/CBC detection oracle
///
/// Now that you have ECB and CBC working:
///
/// Write a function to generate a random AES key; that's just 16 random bytes.
///
/// Write a function that encrypts data under an unknown key --- that is, a function that generates
/// a random key and encrypts under it.
///
/// The function should look like:
///
///     encryption_oracle(your-input)
///     => [MEANINGLESS JIBBER JABBER]
///
/// Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
/// and 5-10 bytes after the plaintext.
///
/// Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half
/// (just use random IVs each time for CBC). Use rand(2) to decide which to use.
///
/// Detect the block cipher mode the function is using each time. You should end up with a piece of
/// code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is
/// happening.

extern crate rand;

use self::rand::Rng;

use util::generate_key;
use util::encryption::{EncryptionMode, cbc_encrypt, ecb_encrypt};
use util::oracles::detect_ecb;


pub fn challenge11() -> Result<String, String> {
    let test_string = vec!['A' as u8; 80];
    for _ in 0..100 {
        let (ciphertext, enc_mode) = stochastic_encrypt(test_string.as_slice());
        if enc_mode != detect_ecb(&ciphertext) {
            return Err(format!("Did not detect that {:?} is encrypted in mode {:?}",
                               ciphertext,
                               enc_mode));
        }
    }
    Ok(String::from("Didn't skip a beat! I know what's up 100% of the time."))
}

fn stochastic_encrypt(plaintext: &[u8]) -> (Vec<u8>, EncryptionMode) {
    let key = generate_key(16);
    let mut rng = rand::thread_rng();

    // Construct the new plaintext that's had random bytes prepended and appended
    let padlen = (rng.gen::<usize>() % 6) + 5;
    let random_bytes = generate_key(padlen);
    let mut padded_plaintext: Vec<u8> = Vec::with_capacity(plaintext.len() + 2 * padlen);
    padded_plaintext.extend(random_bytes.iter());
    padded_plaintext.extend(plaintext.iter());
    padded_plaintext.extend(random_bytes.iter());

    if rng.gen() {
        let iv = generate_key(16);
        (cbc_encrypt(&padded_plaintext, &key, &iv), EncryptionMode::AesCbc)
    } else {
        (ecb_encrypt(&padded_plaintext, &key), EncryptionMode::AesEcb)
    }
}
