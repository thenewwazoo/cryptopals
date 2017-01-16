
extern crate data_encoding;

pub trait FromBase64 {
    fn from_base64(&self) -> Vec<u8>;
}

impl FromBase64 for String {
    fn from_base64(&self) -> Vec<u8> {
        self.chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(decode_b64_chunk)
            .flat_map(|c| c.into_iter())
            .collect::<Vec<u8>>()
    }
}

impl<'a> FromBase64 for &'a str {
    fn from_base64(&self) -> Vec<u8> {
        self.to_string().from_base64()
    }
}

pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl<'a> ToBase64 for &'a [u8] {
    fn to_base64(&self) -> String {
        self.chunks(3)
            .map(|c| b64_map(c))
            .fold(String::new(),
                  |acc, c| acc + &c.iter().cloned().collect::<String>())
    }
}

// Maps a slice, of as many as three bytes, into four base64 characters (including padding)
//
// ```
// assert_eq!( b64_map([0x4d, 0x61, 0x6e]), ['T', 'W', 'F', 'u'] );
// assert_eq!( b64_map([0x4d]), ['T', 'Q', '=', '='] );
// ```
//
fn b64_map(bytes: &[u8]) -> [char; 4] {
    // base64 alphabet, plus the pad character at the end
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // `triword` is a 24-bit representation of `bytes` (stored in a u32)
    let triword: u32 = bytes.iter()
        .zip([2, 1, 0].iter())
        .map(|(&w, &s)| (w as u32) << (8 * s))
        .fold(0, |acc, x| acc + x);

    // Mask the 6-bit portions of `triword`, and store them as indices into `alphabet`
    let indices: Vec<usize> = [18, 12, 6, 0]
        .iter()
        .map(|s| (((triword & (0b111111u32 << s)) >> s) as u8))
        .enumerate()
        .map(|(i, v)| if i <= bytes.len() { v as usize } else { 64 })
        .collect();

    // Extract the characters from `alphabet` into a vector
    let characters: Vec<char> = indices.iter()
        .map(|&v| alphabet[v] as char)
        .collect();
    [characters[0], characters[1], characters[2], characters[3]]
}

fn decode_b64_chunk(input: &[char]) -> Vec<u8> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // Build a 32-bit value out of (up to) 4 base64 characters
    let qw: u32 = input.iter()
        .map(|&c| alphabet.find(c))
        .map(|r| r.expect("Invalid base64 character!") as u8)
        .enumerate()
        .map(|(i, t)| (t as u32) << ((3 - i) * 6))
        .fold(0, |acc, x| acc + x);

    // For each of the three pairs of characters ABCD=>[AB, BC, CD]
    vec![(input[0], input[1]), (input[1], input[2]), (input[2],input[3])]
        .iter()
        // Zip it with the quadword, broken into three 8-bit parts
        .zip([((qw&(0xff<<16))>>16) as u8, ((qw&0xff<<8)>>8) as u8, (qw&0xff) as u8].iter())
        // If the second character in the pair isn't an '='
        .map(|(&(_, c2), qb)| if c2 == '=' { None } else { Some(qb) })
        .filter(|&o| match o { Some(_) => true, _ => false })
        // Keep that byte of the quadword
        .map(|b| b.unwrap())
        .cloned()
        .collect::<Vec<u8>>()
}
