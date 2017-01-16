
pub fn repeating_key_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    plaintext.iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect::<Vec<u8>>()
}
