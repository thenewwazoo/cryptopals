/// Challenge 1
///
/// Convert hex to base64
///
/// The string:
///
/// `49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`
///
/// Should produce:
///
/// `SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`
///
/// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

use util::hex::FromHex;
use util::base64::ToBase64;

pub fn challenge1() -> Result<String, String> {
    let known_text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();
    let decoded = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        .decode_hex()
        .as_slice()
        .to_base64();
    if decoded == known_text {
        Ok(decoded)
    } else {
        Err(format!("{} did not match expected {}", decoded, known_text))
    }
}
