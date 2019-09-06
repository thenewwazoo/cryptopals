pub mod base64 {

    pub const BASE64_MAP: &[u8; 65] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    pub trait ToBase64 {
        fn to_base64(self) -> String;
    }

    impl ToBase64 for &[u8] {
        /// Encode the provided byte slice as base64.
        ///
        /// ```
        /// use arse::encode::base64::ToBase64;
        ///
        /// let input = [0, 0, 1];
        /// let output = "AAAB";
        /// assert_eq!(input.to_base64(), output);
        /// ```
        fn to_base64(self) -> String {
            self.chunks(3)
                .flat_map(|ch| {
                    // Take 24-bit (3-byte) chunks of the input slice and convert them into four 6-bit
                    // characters.

                    // Get the first 6-bit character
                    let first = (ch[0] & 0b1111_1100) >> 2;

                    // There is always a second character because it holds the bottom two bits of the
                    // first input byte.
                    let second = (ch[0] & 0b0000_0011) << 4;

                    // If there is a second input byte, use its top four bits as the bottom bits of the
                    // second output character, or else just leave them as zeroes.
                    let second = second
                        | match ch.get(1) {
                            Some(c) => (c & 0b1111_0000) >> 4,
                            None => 0b0000,
                        };

                    // For the third output character...
                    let third = match (ch.get(1), ch.get(2)) {
                        // If there is no second or third input byte, emit padding for the third output
                        // character.
                        (None, None) => 64,
                        // If there is only a second input byte, we need to get its remaining bottom
                        // four bits and use them as the top of the third output character.
                        (Some(c), None) => (c & 0b0000_1111) << 2,
                        // If there is a third input byte, get its top two bits to finish the third
                        // output character also.
                        (Some(c), Some(d)) => (c & 0b0000_1111) << 2 | (d & 0b1100_0000) >> 6,
                        // There cannot be a third but not a second byte.
                        (None, Some(_)) => unreachable!(),
                    };

                    // For the fourth output character...
                    let fourth = match ch.get(2) {
                        // If there is a third input byte, get its bottom six bits for use as the
                        // fourth output character.
                        Some(d) => d & 0b0011_1111,
                        // or else must emit padding
                        None => 64,
                    };

                    vec![first, second, third, fourth]
                        .iter()
                        .map(|c| char::from(BASE64_MAP[*c as usize]))
                        .collect::<Vec<char>>()
                })
                .collect::<String>()
        }
    }

    #[derive(Debug)]
    pub enum Base64Error {
        BadCharacter(u8),
        Length,
    }

    /// Things that can be decoded from strings into bytes
    pub trait TryFromBase64 {
        fn try_from_base64(self) -> Result<Vec<u8>, Base64Error>;
    }

    impl<T> TryFromBase64 for T
    where
        T: AsRef<str>,
    {
        fn try_from_base64(self) -> Result<Vec<u8>, Base64Error> {
            let parts = self
                .as_ref()
                .trim_end_matches('=')
                .as_bytes()
                .chunks(4)
                .map(|chunk| {
                    fn lookup(a: u8) -> Result<usize, Base64Error> {
                        match BASE64_MAP.iter().position(|b| a.eq(b)) {
                            Some(sz) => Ok(sz),
                            None => Err(Base64Error::BadCharacter(a)),
                        }
                    }

                    if chunk.len() == 1 {
                        return Err(Base64Error::Length);
                    }

                    let mut output: Vec<u8> = Vec::new();

                    output.push(((lookup(chunk[0])? & 0b11_1111) as u8) << 2); // first 6 bits

                    let c1 = lookup(chunk[1])?;
                    output[0] |= ((c1 & 0b0011_0000) as u8) >> 4; // top 2 of second 6 bits

                    if let Some(c) = chunk.get(2) {
                        output.push(((c1 & 0b0000_1111) as u8) << 4); // bottom 4 of second 6 bits
                        let c2 = lookup(*c)?;
                        output[1] |= ((c2 & 0b0011_1100) as u8) >> 2;
                    }

                    if let Some(d) = chunk.get(3) {
                        output.push(((lookup(chunk[2])? & 0b0000_0011) as u8) << 6);
                        output[2] |= (lookup(*d)? & 0b0011_1111) as u8;
                    }

                    Ok(output)
                })
                .collect::<Vec<Result<Vec<u8>, Base64Error>>>();

            let mut output = Vec::new();
            for c in parts.into_iter() {
                output.extend(c?);
            }

            Ok(output)
        }
    }

}

mod test {
    #[test]
    fn test_b64_encode() {
        use crate::encode::base64::ToBase64;

        assert_eq!(
            b"any carnal pleasure.".to_base64(),
            String::from("YW55IGNhcm5hbCBwbGVhc3VyZS4=")
        );

        assert_eq!(
            b"any carnal pleasure".to_base64(),
            String::from("YW55IGNhcm5hbCBwbGVhc3VyZQ==")
        );

        assert_eq!(
            b"any carnal pleasur".to_base64(),
            String::from("YW55IGNhcm5hbCBwbGVhc3Vy")
        );
    }

    #[test]
    fn test_b64_decode() {
        use crate::encode::base64::TryFromBase64;

        assert_eq!(
            "YW55IGNhcm5hbCBwbGVhcw".try_from_base64().unwrap(),
            b"any carnal pleas"
        );

        assert_eq!(
            "YW55IGNhcm5hbCBwbGVhcw==".try_from_base64().unwrap(),
            b"any carnal pleas"
        );

        assert_eq!(
            "YW55IGNhcm5hbCBwbGVhc3U=".try_from_base64().unwrap(),
            b"any carnal pleasu"
        );

        assert_eq!(
            "YW55IGNhcm5hbCBwbGVhc3U".try_from_base64().unwrap(),
            b"any carnal pleasu"
        );

        assert_eq!(
            "YW55IGNhcm5hbCBwbGVhc3Vy".try_from_base64().unwrap(),
            b"any carnal pleasur"
        );

        assert!("ABCDE===".try_from_base64().is_err());

        assert!("ABCDE".try_from_base64().is_err());
    }
}

pub mod hex {
    use std::num::ParseIntError;

    pub trait TryFromHex {
        /// Decode the given hex-encoded UTF-8 string into bytes
        ///
        /// ```
        /// use arse::encode::hex::TryFromHex;
        ///
        /// assert_eq!("FF".try_from_hex().unwrap(), vec![0xFF]);
        /// assert_eq!("00".try_from_hex().unwrap(), vec![0x00]);
        /// assert!("JJ".try_from_hex().is_err(), "should not be able to decode 0xJJ");
        /// assert_eq!("ABCD".try_from_hex().unwrap(), vec![0xAB, 0xCD]);
        /// ```
        fn try_from_hex(self) -> Result<Vec<u8>, HexError>;
    }

    impl<T> TryFromHex for T
    where
        T: AsRef<str>,
    {
        fn try_from_hex(self) -> Result<Vec<u8>, HexError> {
            self.as_ref()
                .as_bytes()
                .chunks(2)
                .map(|ch| {
                    let formatted = format!("{}{}", char::from(ch[0]), char::from(ch[1]));
                    u8::from_str_radix(&formatted, 16).map_err(|e| e.into())
                })
                .collect::<Result<Vec<u8>, HexError>>()
        }
    }

    #[derive(Debug)]
    pub enum HexError {
        BadCharacter,
        Length,
    }

    impl From<ParseIntError> for HexError {
        fn from(_: ParseIntError) -> Self {
            HexError::BadCharacter
        }
    }

    pub trait ToHex {
        /// Hex-encode the given bytes into a string
        ///
        /// ```
        /// use arse::encode::hex::ToHex;
        /// assert_eq!([0].to_hex(), String::from("00"));
        /// assert_eq!([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0].to_hex(), "123456789abcdef0");
        /// ```
        fn to_hex(self) -> String;
    }

    impl<T> ToHex for T
    where
        T: AsRef<[u8]>,
    {
        fn to_hex(self) -> String {
            use std::char::from_digit;

            self.as_ref()
                .iter()
                .map(|t| ((t >> 4) as u8, t & 0b1111))
                .fold(String::new(), |mut acc, (l, h)| {
                    acc.push(from_digit(l.into(), 16).unwrap().to_ascii_lowercase());
                    acc.push(from_digit(h.into(), 16).unwrap().to_ascii_lowercase());
                    acc
                })
        }
    }

}
