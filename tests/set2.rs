/// # Implement PKCS#7 padding
///
/// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into
/// ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized
/// messages.
///
/// One way we account for irregularly-sized messages is by padding, creating a plaintext that is
/// an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
///
/// So: pad any block to a specific block length, by appending the number of bytes of padding to
/// the end of the block. For instance,
///
/// `YELLOW SUBMARINE`
///
/// ... padded to 20 bytes would be:
///
/// `YELLOW SUBMARINE\x04\x04\x04\x04`
#[test]
fn challenge9() {
    use arse::transform::pkcs7_pad;

    assert_eq!(
        pkcs7_pad(b"YELLOW SUBMARINE".to_vec(), 20).unwrap(),
        b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
    );
}

/// # Implement CBC mode
///
/// CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite
/// the fact that a block cipher natively only transforms individual blocks.
///
/// In CBC mode, each ciphertext block is added to the next plaintext block before the next call to
/// the cipher core.
///
/// The first plaintext block, which has no associated previous ciphertext block, is added to a
/// "fake 0th ciphertext block" called the initialization vector, or IV.
///
/// Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt
/// instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR
/// function from the previous exercise to combine them.
///
/// The file [here](https://cryptopals.com/static/challenge-data/10.txt) is intelligible (somewhat)
/// when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
///
/// > Don't cheat.
/// >
/// > Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point
/// > of even doing this stuff if you aren't going to learn from it?
#[test]
fn challenge10() {
    use arse::encode::base64::TryFromBase64;
    use arse::encrypt::cbc_decrypt;

    const KEY: &[u8] = b"YELLOW SUBMARINE";

    let mut ciphertext = include_str!("data/10.txt").to_string();
    ciphertext.retain(|c| !c.is_whitespace());
    let ciphertext = ciphertext.try_from_base64().unwrap();

    let _cleartext = String::from_utf8_lossy(&cbc_decrypt(&KEY, &ciphertext).unwrap());
    //println!("Challenge 10: {}", cleartext);
}
