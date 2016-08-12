/// Challenge 1
///
/// Convert hex to base64
///
/// The string:
///
/// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
///
/// Should produce:
///
/// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
///
/// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

pub fn b64_encode(hex_input: &str) -> String {
    hex_decode(hex_input)
        .chunks(3)
        .map(|c| b64_map(c))
        .collect::<Vec<_>>()
        .iter()
        .fold(String::new(), |acc, c| acc + &(c.iter().cloned().collect::<String>()))
}

pub fn hex_decode(hex_input: &str) -> Vec<u8> {
    hex_input
        .to_string()
        .to_lowercase()
        .chars()
        .map(hex_map)
        .collect::<Vec<u8>>()
        .chunks(2)
        .map(|c| (c[0]<<4) + c[1])
        .collect()
}

pub fn hex_map(c: char) -> u8 {
    match c {
        '0' => 0,  '1' => 1,  '2' => 2,  '3' => 3,
        '4' => 4,  '5' => 5,  '6' => 6,  '7' => 7,
        '8' => 8,  '9' => 9,  'a' => 10, 'b' => 11,
        'c' => 12, 'd' => 13, 'e' => 14, 'f' => 15,
        _ => panic!("not a hex character")
    }
}

/// Maps a slice, of as many as three bytes, into four base64 characters (including padding)
///
///  # Examples
/// assert_eq!( b64_map([0x4d, 0x61, 0x6e]), ['T', 'W', 'F', 'u'] );
/// assert_eq!( b64_map([0x4d]), ['T', 'Q', '=', '='] );
///
fn b64_map(bytes: &[u8]) -> [char; 4] {
    // base64 alphabet, plus the pad character at the end
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".as_bytes();

    // `triword` is a 24-bit representation of `bytes` (stored in a u32)
    let triword: u32 = bytes
        .iter()
        .zip([2, 1, 0].iter())
        .map(|(&w,&s)| (w as u32) << (8*s))
        .fold(0, |acc, x| acc + x);

    // Mask the 6-bit portions of `triword`, and store them as indices into `alphabet`
    let indices: Vec<usize> = [18, 12, 6, 0]
        .iter()
        .map(|s| (((triword & (0b111111u32 << s)) >> s) as u8))
        .enumerate()
        .map(|(i, v)| if i <= bytes.len() {v as usize} else {64})
        .collect();

    // Extract the characters from `alphabet` into a vector
    let characters: Vec<char> = indices
        .iter()
        .map(|&v| alphabet[v] as char)
        .collect();
    [characters[0], characters[1], characters[2], characters[3]]
}
