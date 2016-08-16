// Challenge 5
//
// Implement repeating-key XOR
//
// Here is the opening stanza of an important work of the English language:
//
//     Burning 'em, if you ain't quick and nimble
//     I go crazy when I hear a cymbal
//
// Encrypt it, under the key "ICE", using repeating-key XOR.
//
// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of
// plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so
// on.
//
// It should come out to:
//
// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
//
// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your
// password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with
// this.

pub fn rcx(key: &[u8], plaintext: &str) -> String {
    hex_encode(
        plaintext
        .as_bytes()
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect::<Vec<u8>>()
        .as_slice()
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|&b| nibble_map(b).into_iter())
        .collect()
}

fn nibble_map(b: u8) -> Vec<char> {
    [b >> 4, b & 0b1111]
        .iter()
        .map(|&h| match h {
            0x0u8 => '0', 0x1u8 => '1', 0x2u8 => '2', 0x3u8 => '3',
            0x4u8 => '4', 0x5u8 => '5', 0x6u8 => '6', 0x7u8 => '7',
            0x8u8 => '8', 0x9u8 => '9', 0xau8 => 'a', 0xbu8 => 'b',
            0xcu8 => 'c', 0xdu8 => 'd', 0xeu8 => 'e', 0xfu8 => 'f',
            _ => panic!("Value not in range 0x0-0xf")
        })
        .collect()
}
