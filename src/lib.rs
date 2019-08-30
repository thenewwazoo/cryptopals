pub mod xor_cipher {
    use super::stat::{Histogram, HistogramError};
    use super::transform::TryFixedXor;
    use std::f32;

    pub fn score_byte_decode(
        test_byte: u8,
        ciphertext: &[u8],
        language: &Histogram<char>,
    ) -> Result<f32, HistogramError> {
        let bytes = ciphertext
            .try_fixed_xor(vec![test_byte; ciphertext.len()].as_slice())
            .unwrap();
        let b_len = bytes.len();

        match String::from_utf8(bytes) {
            Ok(s) => {
                if s.len() != b_len {
                    return Err(HistogramError::HistogramMismatch);
                }
                let s = s
                    .to_lowercase()
                    .chars()
                    .filter(|&c| c.is_alphabetic())
                    .collect::<String>();
                if s.len() == 0 {
                    return Err(HistogramError::HistogramMismatch);
                }

                let mut byte_distr: Histogram<char> = s.chars().into();
                byte_distr.normalize();
                match byte_distr.chisq(language) {
                    Ok(raw_score) => {
                        let pct_non_alpha = (b_len - s.len()) as f32 / b_len as f32;
                        Ok(raw_score * pct_non_alpha)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => Err(HistogramError::HistogramMismatch),
        }
    }
}

pub mod stat {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::f32;
    use std::hash::Hash;

    /// A HashMap of `f32`-valued buckets whose chi-squared goodness of fit can be calculated.
    pub struct Histogram<T>(pub HashMap<T, f32>);

    /// Possible errors when trying to calculate goodness-of-fit values for a `Histogram`
    #[derive(Debug, Eq, PartialEq)]
    pub enum HistogramError {
        BucketNotFound,
        HistogramMismatch,
    }

    impl<T> Histogram<T>
    where
        T: Hash + Eq,
    {
        /// Calculate the chi-squared goodness-of-fit metric between this and a baseline histogram.
        /// Returns a single dimensionless value, with 0 being an exact match.
        pub fn chisq(&self, baseline: &Histogram<T>) -> Result<f32, HistogramError> {
            self.0
                .iter()
                .map(|(item, freq)| match baseline.0.get(item) {
                    Some(b_freq) => Ok((freq - b_freq) * (freq - b_freq) / (freq + b_freq)),
                    None => Err(HistogramError::BucketNotFound),
                })
                .collect::<Result<Vec<f32>, HistogramError>>()
                .map(|v| v.iter().sum())
        }

        /// Normalize this histogram, making all values sum to 1.
        pub fn normalize(&mut self) {
            let len = self.0.iter().len();
            self.0.iter_mut().for_each(|(_, n)| *n = *n / (len as f32));
        }
    }

    /// Create a histogram from a source corpus, counting each occurrence of a value iterated over,
    /// and with each value used to key the map.
    impl<V, K> From<V> for Histogram<K>
    where
        K: Hash + Eq,
        V: Iterator<Item = K>,
    {
        fn from(list: V) -> Self {
            Histogram(list.into_iter().fold(HashMap::new(), |mut acc, i| {
                match acc.entry(i) {
                    Entry::Occupied(mut e) => {
                        e.insert(*(e.get()) + 1f32);
                    } // increase count by 1.0
                    Entry::Vacant(e) => {
                        e.insert(1f32);
                    } // store 1.0 if not found
                };
                acc
            }))
        }
    }
}

pub mod transform {

    use std::ops::BitXor;

    #[derive(Debug)]
    pub enum TransformError {
        MismatchedLengths,
    }

    pub trait TryFixedXor<T>
    where
        T: BitXor,
    {
        /// For two slices of equivalent fixed length, perform a bytewise XOR.
        ///
        /// ```
        /// use arse::transform::TryFixedXor;
        ///
        /// let a: &[u8] = &[0x00, 0x00];
        /// let b: &[u8] = &[0xFF, 0xFF];
        /// let c: &[u8] = &[0xFF, 0xFF, 0xFF];
        /// let z: Vec<u8> = vec![0xFF, 0xFF];
        ///
        /// assert_eq!(a.try_fixed_xor(b).unwrap(), z);
        /// assert!(a.try_fixed_xor(c).is_err());
        /// ```
        fn try_fixed_xor(&self, other: &[T]) -> Result<Vec<T::Output>, TransformError>;
    }

    impl TryFixedXor<u8> for &[u8] {
        fn try_fixed_xor(&self, other: &[u8]) -> Result<Vec<u8>, TransformError> {
            if &self.into_iter().len() != &other.into_iter().len() {
                Err(TransformError::MismatchedLengths)
            } else {
                Ok(self
                    .into_iter()
                    .zip(other.into_iter())
                    .map(|(s, o)| s ^ o)
                    .collect())
            }
        }
    }

    /// Encode the provided byte slice as base64.
    ///
    /// ```
    /// use arse::transform::base64_encode;
    ///
    /// let input = [0, 0, 1];
    /// let output = "AAAB";
    /// assert_eq!(base64_encode(&input), output);
    /// ```
    pub fn base64_encode(input: &[u8]) -> String {
        const BASE64_MAP: &[u8; 65] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        input.chunks(3).fold(String::new(), |mut acc, ch| {
            // 24-bit chunks

            let first = (ch[0] & 0b1111_1100) >> 2;

            let second = match ch.get(1) {
                Some(c) => (ch[0] & 0b0000_0011) << 4 | (c & 0b1111_0000) >> 4,
                None => 64,
            };

            let third = match (ch.get(1), ch.get(2)) {
                (Some(c), Some(d)) => (c & 0b0000_1111) << 2 | (d & 0b1100_0000) >> 6,
                (None, Some(_)) => unreachable!(),
                (_, None) => 64,
            };

            let fourth = match ch.get(2) {
                Some(d) => d & 0b0011_1111,
                None => 64,
            };

            let b64_raw = vec![first, second, third, fourth];

            for bch in b64_raw {
                acc.push_str(&format!("{}", char::from(BASE64_MAP[bch as usize])));
            }

            acc
        })
    }

    /// Decode the given hex-encoded UTF-8 string into bytes
    ///
    /// ```
    /// use arse::transform::hex_decode;
    ///
    /// assert_eq!(hex_decode("FF"), Ok(vec![0xFF]));
    /// assert_eq!(hex_decode("00"), Ok(vec![0x00]));
    /// assert!(hex_decode("JJ").is_err(), "should not be able to decode 0xJJ");
    /// assert_eq!(hex_decode("ABCD"), Ok(vec![0xAB, 0xCD]));
    /// ```
    use std::num::ParseIntError;
    pub fn hex_decode(input: &str) -> Result<Vec<u8>, ParseIntError> {
        input
            .as_bytes()
            .chunks(2)
            .map(|ch| {
                let formatted = format!("{}{}", char::from(ch[0]), char::from(ch[1]));
                u8::from_str_radix(&formatted, 16)
            })
            .collect::<Result<Vec<u8>, ParseIntError>>()
    }

    /// Hex-encode the given bytes into a string
    ///
    /// ```
    /// use arse::transform::hex_encode;
    /// assert_eq!(hex_encode(&[0]), String::from("00"));
    /// assert_eq!(hex_encode(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]), "123456789abcdef0");
    /// ```
    use std::char::from_digit;
    pub fn hex_encode(input: &[u8]) -> String {
        input
            .iter()
            .map(|t| ((t >> 4) as u8, t & 0b1111))
            .fold(String::new(), |mut acc, (l, h)| {
                acc.push(from_digit(l.into(), 16).unwrap().to_ascii_lowercase());
                acc.push(from_digit(h.into(), 16).unwrap().to_ascii_lowercase());
                acc
            })
    }

}

mod test {
    #[test]
    fn test_b64() {
        use crate::transform::base64_encode;

        let input = [0xFF, 0xFF, 0xFF];
        let output = "////";
        assert_eq!(base64_encode(&input), output);

        let input = [0, 0, 0];
        let output = "AAAA";
        assert_eq!(base64_encode(&input), output);

        let input = [0, 0, 0, 0];
        let output = "AAAAA===";
        assert_eq!(base64_encode(&input), output);
    }
}
