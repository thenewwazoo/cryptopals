
use std::cmp::Ordering::Greater;
use std::collections::HashMap;
use std::f32;

use util::bit_manip::bytewise_xor;

// XOR each byte of ciphertext with each value of a byte 0..254. For each resultant byte string,
// convert to a utf8 String; if successful, score the likelihood of that result being English text.
// Return a list of scores, byte values, and the resulting strings.
// pub fn score_byte_space(ciphertext: &Vec<u8>) -> Vec<(f32, u8, String)> {
pub fn score_byte_space(ciphertext: &[u8]) -> Vec<(f32, u8, String)> {
    let mut scores: Vec<(f32, u8, String)> = (0..254)
        .map(|k| {
            (k, String::from_utf8(bytewise_xor(ciphertext, vec![k; ciphertext.len()].as_slice())))
        })
        .filter(|&(_, ref b)| match *b {
            Ok(_) => true,
            _ => false,
        })
        .map(|(k, b)| {
            let b = b.unwrap();
            (score_plaintext(&b), k, b.clone())
        })
        .collect();
    scores.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Greater)); // laziness defeats in-place sorts
    scores
}

// Given a string of text, calculate the chi-squared distance between its letter frequency
// distribution and that of typical English text. Also calculate what percentage of its characters
// are non-alphanumeric, as a measure of how good a sample of text we've got (for example, we may
// not be confident in our score for text with lots of punctuation).
//
// Return the product of the chi-squared distance and the percentage; lower is better.
pub fn score_plaintext(plaintext: &str) -> f32 {
    let freq_table: Vec<(char, f32)> = vec![('e', 0.12702),
                                            ('t', 0.09056),
                                            ('a', 0.08167),
                                            ('o', 0.07507),
                                            ('i', 0.06966),
                                            ('n', 0.06749),
                                            ('s', 0.06327),
                                            ('h', 0.06094),
                                            ('r', 0.05987),
                                            ('d', 0.04253),
                                            ('l', 0.04025),
                                            ('c', 0.02782),
                                            ('u', 0.02758),
                                            ('m', 0.02406),
                                            ('w', 0.02360),
                                            ('f', 0.02228),
                                            ('g', 0.02015),
                                            ('y', 0.01974),
                                            ('p', 0.01929),
                                            ('b', 0.01492),
                                            ('v', 0.00978),
                                            ('k', 0.00772),
                                            ('j', 0.00153),
                                            ('x', 0.00150),
                                            ('q', 0.00095),
                                            ('z', 0.00074),
                                            ('\u{0}', f32::MAX)];
    let mut freq_map: HashMap<char, f32> = HashMap::new();
    for t in freq_table {
        freq_map.insert(t.0, t.1);
    } // there's not really a way to declare a HashMap in-place in Rust, I guess?

    let clean_text: String = plaintext.to_string()
        .to_lowercase()
        .chars()
        .filter(|&c| "abcdefghijklmnopqrstuvwxyz\u{0}".contains(c))
        .collect();
    let count = count_chars(&clean_text);
    let pct_non_alpha = (plaintext.len() - clean_text.len()) as f32 / plaintext.len() as f32;

    let freq_distance = if !clean_text.is_empty() {
        chisq(normalize_frequencies(count, clean_text.len()), freq_map)
    } else {
        f32::MAX // if there are no alphanumeric characters it's probably not English
    };

    // the better a sample we get, the more confident we are in the distance calculation
    freq_distance * pct_non_alpha

}

fn count_chars(text: &str) -> HashMap<char, u32> {
    let mut count: HashMap<char, u32> = HashMap::new();
    for c in text.to_lowercase().chars() {
        *count.entry(c).or_insert(0) += 1;
    }
    count
}

fn normalize_frequencies(count: HashMap<char, u32>, length: usize) -> HashMap<char, f32> {
    let mut normed: HashMap<char, f32> = HashMap::new();
    for (&c, &n) in &count {
        let _ = normed.insert(c, n as f32 / length as f32);
    }
    normed
}

fn chisq(input: HashMap<char, f32>, baseline: HashMap<char, f32>) -> f32 {
    input.iter()
        .collect::<Vec<_>>()
        .iter()
        .map(|&(ch, &pct)| {
            let g = baseline[ch];
            let f = pct;
            (f - g) * (f - g) / (f + g)
        })
        .fold(0.0, |acc, x| acc + x)
}

// Calculate the hamming distance between two byte sequences
pub fn hamming_dist(left: &[u8], right: &[u8]) -> u32 {
    assert_eq!(left.len(), right.len());
    left.iter()
        .zip(right.iter())
        .fold(0, |acc, (&l, &r)| acc + (l ^ r).count_ones())
}
