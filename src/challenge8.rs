// Challenge 8
//
// Detect AES in ECB mode
//
// In 8.txt are a bunch of hex-encoded ciphertexts.
//
// One of them has been encrypted with ECB.
//
// Detect it.
//
// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte
// plaintext block will always produce the same 16 byte ciphertext.


use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use challenge1::hex_decode;

pub fn detect_ecb(ciphertext: &[u8]) -> bool {
    let chunks = ciphertext.chunks(16);
    let mut map: HashMap<&[u8], u32> = HashMap::new();
    for chunk in chunks {
        *map.entry(chunk).or_insert(0) += 1;
    }
    for (_, count) in map {
        if count > 1 {
            return true;
        }
    }
    false
}

pub fn detect_ecb_line(filename: &str) -> Option<String> {

    let mut is_ecb: HashMap<String, bool> = HashMap::new();
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        let line = line.unwrap();
        let decoded = hex_decode(&line);
        is_ecb.insert(line, detect_ecb(&decoded));
    }
    for (line, is_line_ecb) in is_ecb {
        if is_line_ecb {
            return Some(line);
        }
    }
    None
}
