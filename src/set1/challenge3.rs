/// Challenge 3
///
/// Single-byte XOR cipher
///
/// The hex encoded string:
///
/// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
///
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a
/// good metric. Evaluate each output and choose the one with the best score.

use util::stat::score_byte_space;
use util::hex::FromHex;

pub fn decrypt_message(ciphertext: &str) -> String {
    let results = score_byte_space(&ciphertext.decode_hex());
    results[0].2.clone() // return the best-scoring result
}

pub fn challenge3() -> Result<String, String>
{
    let plaintext = "Cooking MC's like a pound of bacon";
    let decrypted = decrypt_message("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    if plaintext == decrypted {
        Ok(decrypted)
    } else {
        Err(format!("{} does not match expected result {}", decrypted, plaintext))
    }
}

