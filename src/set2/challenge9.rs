/// Challenge 9
///
/// Implement PKCS#7 padding
///
/// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into
/// ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized
/// messages.
///
/// One way we account for irregularly-sized messages is by padding, creating a plaintext that is an
/// even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
///
/// So: pad any block to a specific block length, by appending the number of bytes of padding to the
/// end of the block. For instance,
///
///     "YELLOW SUBMARINE"
///
/// ... padded to 20 bytes would be:
///
///     "YELLOW SUBMARINE\x04\x04\x04\x04"

use util::pkcs7_pad_block;

pub fn challenge9() -> Result<String, String>
{
    let input_block = "YELLOW SUBMARINE".as_bytes();
    let known_good = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();
    let desired_len = 20;

    let padded = pkcs7_pad_block(input_block, 20).unwrap();

    if padded == known_good {
        Ok(format!("Padded {:?} to {} bytes ok: {:?}", input_block, desired_len, padded))
    } else {
        Err(format!("{:?} does not pad {:?} to {} bytes correctly", padded, input_block, desired_len))
    }
}
