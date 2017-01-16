
pub trait FromHex {
    fn decode_hex(&self) -> Vec<u8>;
}

impl<'a> FromHex for &'a str {
    fn decode_hex(&self) -> Vec<u8> {
        self.to_string()
            .to_lowercase()
            .chars()
            .map(hex_map)
            .collect::<Vec<u8>>()
            .chunks(2)
            .map(|c| (c[0] << 4) + c[1])
            .collect()
    }
}

// Deref coersion seems to be wonky? so this.
impl<'a> FromHex for String {
    fn decode_hex(&self) -> Vec<u8> {
        (&self[..]).decode_hex()
    }
}

pub trait ToHex {
    fn encode_hex(&self) -> String;
}

impl<'a> ToHex for &'a [u8] {
    fn encode_hex(&self) -> String {
        self.iter()
            .flat_map(|&b| nibble_map(b).into_iter())
            .collect()
    }
}

impl<'a> ToHex for Vec<u8> {
    fn encode_hex(&self) -> String {
        (&self[..]).encode_hex()
    }
}

pub fn hex_map(c: char) -> u8 {
    match c {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'a' => 10,
        'b' => 11,
        'c' => 12,
        'd' => 13,
        'e' => 14,
        'f' => 15,
        _ => panic!("not a hex character"),
    }
}

fn nibble_map(b: u8) -> Vec<char> {
    [b >> 4, b & 0b1111]
        .iter()
        .map(|&h| match h {
            0x0u8 => '0',
            0x1u8 => '1',
            0x2u8 => '2',
            0x3u8 => '3',
            0x4u8 => '4',
            0x5u8 => '5',
            0x6u8 => '6',
            0x7u8 => '7',
            0x8u8 => '8',
            0x9u8 => '9',
            0xau8 => 'a',
            0xbu8 => 'b',
            0xcu8 => 'c',
            0xdu8 => 'd',
            0xeu8 => 'e',
            0xfu8 => 'f',
            _ => panic!("Value not in range 0x0-0xf"),
        })
        .collect()
}
