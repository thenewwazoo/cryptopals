/// Challenge 8
///
/// Detect AES in ECB mode
///
/// In 8.txt are a bunch of hex-encoded ciphertexts.
///
/// One of them has been encrypted with ECB.
///
/// Detect it.
///
/// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte
/// plaintext block will always produce the same 16 byte ciphertext.

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

use util::hex::{FromHex, ToHex};
use util::oracles::detect_ecb;
use util::encryption::EncryptionMode;

pub fn challenge8() -> Result<String, String> {
    let filename = "8.txt";

    let ecb_lines = BufReader::new(File::open(filename).unwrap())
        .lines()
        .map(|l| l.unwrap().decode_hex())
        .filter(|l| match detect_ecb(l) {
            EncryptionMode::AesEcb => true,
            EncryptionMode::AesCbc => false,
        })
        .map(|v| v.encode_hex())
        .collect::<Vec<String>>();
    if ecb_lines.len() == 1 {
        let result = &ecb_lines[0];
        Ok(String::from(&result[..8]))
    } else {
        Err(format!("Found {} lines that seem to be ecb. wtf?", ecb_lines.len()))
    }
}
