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

pub fn detect_ecb(filename: &str) -> String {

    let mut result = String::new();
    let mut freq_maps: HashMap<String, HashMap<[u32; 4], u32>> = HashMap::new();
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        let line = line.unwrap();
        let mut freq_map: HashMap<[u32; 4], u32> = HashMap::new();
        let chunks = line
            .as_bytes()
            .chunks(32) // 32 halfwords = 128 bits
            .map(|c| c
                 .chunks(8) // 8 halfwords = 32 bits
                 .map(|c| u32::from_str_radix(&String::from_utf8(c.to_vec()).unwrap(), 16).unwrap() )
                 .collect::<Vec<u32>>()
                 )
            .map(|v| [v[0], v[1], v[2], v[3]])
            .collect::<Vec<[u32; 4]>>();
        for chunk in chunks {
            *freq_map.entry(chunk).or_insert(0) += 1;
        }
        freq_maps.insert(line, freq_map);
    }
    for (line, map) in freq_maps {
        for (_, &v) in map.iter() {
            if v > 1 {
                result = line.clone();
                break;
            }
        }
    }
    result
}
