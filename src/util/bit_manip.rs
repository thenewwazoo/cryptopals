pub fn bytewise_xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    assert_eq!(left.len(), right.len());
    left
        .iter()
        .zip(right.iter())
        .map(|(&l, &r)| l^r)
        .collect::<Vec<u8>>()
}
