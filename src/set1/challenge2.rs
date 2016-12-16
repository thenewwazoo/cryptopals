/// Challenge 2
///
/// Fixed XOR
///
/// Write a function that takes two equal-length buffers and produces their XOR combination.
///
/// If your function works properly, then when you feed it the string:
///
/// 1c0111001f010100061a024b53535009181c
///
/// ... after hex decoding, and when XOR'd against:
///
/// 686974207468652062756c6c277320657965
///
/// ... should produce:
///
/// 746865206b696420646f6e277420706c6179

use util::bit_manip;
use util::hex::{FromHex,ToHex};

pub fn challenge2() -> Result<Vec<u8>, String>
{
    let known_string = "746865206b696420646f6e277420706c6179";
    let result = bit_manip::bytewise_xor(
        "1c0111001f010100061a024b53535009181c".decode_hex().as_slice(),
        "686974207468652062756c6c277320657965".decode_hex().as_slice()
    );
    if known_string.decode_hex() == result {
        Ok(result)
    } else {
        Err(format!("{} does not match expected {}", known_string, result.encode_hex()))
    }
}
