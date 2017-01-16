
use std::collections::HashMap;

use util::generate_key;
use util::encryption::EncryptionMode;

pub fn detect_ecb(ciphertext: &[u8]) -> EncryptionMode {
    let chunks = ciphertext.chunks(16);
    let mut map: HashMap<&[u8], u32> = HashMap::new();
    for chunk in chunks {
        *map.entry(chunk).or_insert(0) += 1;
    }

    if *map.values().max().unwrap() > 1 {
        EncryptionMode::AesEcb
    } else {
        EncryptionMode::AesCbc
    }
}

pub fn find_blocklen(enc: fn(&[u8], &[u8]) -> Vec<u8>) -> Result<usize, String> {
    let key = generate_key(16);
    let mut detected_lengths = Vec::new();
    for l in 1..128 {
        let input = vec![b'A'; l];
        detected_lengths.push(enc(&input, &key).len());
        detected_lengths.dedup();
    }
    let mut sizes = detected_lengths.windows(2).map(|w| w[1] - w[0]).collect::<Vec<usize>>();
    sizes.dedup();

    match sizes.len() {
        1 => Ok(sizes[0]),
        _ => Err(String::from("Could not converge on a block size")),
    }
}
