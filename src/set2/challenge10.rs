/// Challenge 10
///
/// Implement CBC mode
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
/// File 10.txt is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an
/// IV of all ASCII 0 (\x00\x00\x00 &c)

use util::encryption::cbc_decrypt_file;

pub fn challenge10() -> Result<String, String>
{
    let filename = "10.txt";
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = &[0 as u8; 16];

    Ok(String::from_utf8(cbc_decrypt_file(filename, key, iv)).unwrap())
}
