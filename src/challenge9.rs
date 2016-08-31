// Challenge 1
//
// Implement PKCS#7 padding
//
// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into
// ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized
// messages.
//
// One way we account for irregularly-sized messages is by padding, creating a plaintext that is an
// even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
//
// So: pad any block to a specific block length, by appending the number of bytes of padding to the
// end of the block. For instance,
//
// "YELLOW SUBMARINE"
//
// ... padded to 20 bytes would be:
//
// "YELLOW SUBMARINE\x04\x04\x04\x04"

pub fn do_challenge() -> Vec<u8> {
    pad_block("YELLOW SUBMARINE".as_bytes(), 20, b'\x04').unwrap()
}

pub fn pad_block(block: &[u8], len: usize, padchar: u8) -> Result<Vec<u8>, String> {
    if block.len() > len {
        return Err("padlen less than blocklen".to_string());
    }
    let mut result = block.to_vec();
    let mut pad = vec![padchar; len - block.len()];
    result.append(&mut pad);
    Ok(result)
}
