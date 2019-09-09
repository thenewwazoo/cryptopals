/// Traits useful for transforming data
use std::ops::BitXor;

/// Indication that transformation has failed.
#[derive(Debug)]
pub enum TransformError {
    /// Cannot fixed-xor slices of differing length.
    MismatchedLengths,
}

/// XOR two slices of the same length
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

/// XOR two slices of differing length
pub trait XorWith<T: BitXor + Copy> {
    /// For any two slices, xor them together, with the result being the length of the longest
    /// slice.
    ///
    /// ```
    /// use arse::transform::XorWith;
    ///
    /// let a: &[u8] = &[0x00, 0x00];
    /// let b: &[u8] = &[0xFF, 0xFF];
    /// let c: &[u8] = &[0xFF, 0xFF, 0xFF];
    /// let z: Vec<u8> = vec![0xFF, 0xFF];
    ///
    /// assert_eq!(a.xor_with(b), b);
    /// assert_eq!(a.xor_with(c), c);
    /// ```
    fn xor_with<U: AsRef<[T]>>(&self, other: U) -> Vec<T::Output>;
}

impl<T, U> XorWith<T> for U
where
    T: BitXor + Copy,
    U: AsRef<[T]>,
{
    fn xor_with<V: AsRef<[T]>>(&self, other: V) -> Vec<T::Output> {
        let result_len = self.as_ref().len().max(other.as_ref().len());
        self.as_ref()
            .iter()
            .cycle()
            .take(result_len)
            .zip(other.as_ref().iter().cycle().take(result_len))
            .map(|(i, k)| *i ^ *k)
            .collect::<Vec<T::Output>>()
    }
}

/// Indication that the PKCS#7 padding operation failed
#[derive(Debug)]
pub struct Pkcs7PadErr;

use std::u8;

/// Pad the input to length `len` with a repeated byte value equal to the number of padding
/// bytes added. Returns an error if more than 255 padding bytes would be added.
///
/// ```
/// use arse::transform::pkcs7_pad;
///
/// assert_eq!(
///     pkcs7_pad(b"YELLOW SUBMARINE".to_vec(), 20).unwrap(),
///     b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec()
///     );
/// assert!(pkcs7_pad(b"too much padding".to_vec(), 1024).is_err());
/// ```
pub fn pkcs7_pad(mut input: Vec<u8>, len: usize) -> Result<Vec<u8>, Pkcs7PadErr> {
    if len > usize::from(u8::MAX) {
        return Err(Pkcs7PadErr);
    }

    let pad_len = len - input.len();
    input.append(&mut vec![pad_len as u8; pad_len]);
    Ok(input)
}
