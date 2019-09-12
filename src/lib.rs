/// Solutions to the [Cryptopals Challenges](https://cryptopals.com)
///
/// Written whilst leading the *A*spiring *R*ustacean *S*ocial *E*ducation group within LinkedIn
pub mod encode;
pub mod encrypt;
pub mod stat;
pub mod transform;

pub mod xor_cipher {
    use super::stat::{Histogram, HistogramError};
    use super::transform::TryFixedXor;
    use std::f64;

    /// Bytewise XOR `ciphertext` with `test_byte`, and then measure the chi-square goodness of fit
    /// of the resulting output with `language`.
    pub fn score_byte_decode(
        test_byte: u8,
        ciphertext: &[u8],
        language: &Histogram<char>,
    ) -> Result<f64, HistogramError> {
        let bytes = ciphertext
            .try_fixed_xor(vec![test_byte; ciphertext.len()].as_slice())
            .unwrap();
        let b_len = bytes.len();

        match String::from_utf8(bytes) {
            Ok(s) => {
                if s.len() != b_len {
                    return Err(HistogramError::HistogramMismatch);
                }

                // if the resulting string contains a null byte, it's not printable and can be
                // discarded immediately.
                if s.contains(|c| c == '\0') {
                    return Ok(f64::MAX);
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
                        let pct_non_alpha = (b_len - s.len()) as f64 / b_len as f64;
                        Ok(raw_score * pct_non_alpha)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => Err(HistogramError::HistogramMismatch),
        }
    }
}
