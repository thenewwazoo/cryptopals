use std::cmp::Ordering::Equal;
use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;

use challenge3;
use challenge5;

pub fn decipher_text(filename: &str) -> Vec<u8> {
    let ciphertext: String = BufReader::new(File::open(filename).unwrap())
        .lines()
        .fold(String::new(), |acc, l| acc + &(l.unwrap()));
    let ciphertext = b64_decode(&ciphertext[..]);

    let stride = 16;
    let mut key_distances: Vec<(u8, f32)> = (1..40)
        .map(|key_len| (key_len,
                        (0..stride)
                        .map(|i| &ciphertext[(i * (key_len as usize))..((i+1) * (key_len as usize))])
                        .collect::<Vec<&[u8]>>()
                        .as_slice()
                        .chunks(2)
                        .map(|p| hamming_dist(p[0], p[1]) as f32)
                        .fold(0.0, |acc, d| acc + d) / stride as f32 / 2.0 / (key_len as f32)
                       ))
        .collect();
    key_distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Equal));

    let (key_size, _key_score) = key_distances[0];
    let c_chunks = ciphertext
        .chunks(key_size as usize)
        .collect::<Vec<&[u8]>>();

    let transposed = (0..key_size)
        .map(|i| c_chunks
             .iter()
             .map(|&c| c.get(i as usize))
             .filter(|&o| match o {
                 Some(_) => true,
                 _ => false
             })
             .map(|c| *(c.unwrap()))
             .collect::<Vec<u8>>())
        .collect::<Vec<Vec<u8>>>();

    let rowscores: Vec<Vec<(f32, u8, String)>> = transposed
        .iter()
        .map(|row| challenge3::search_xor_space(row))
        .collect();

    let key: Vec<u8> = rowscores
        .iter()
        .map(|r| r[0].1)
        .collect();
    let _ = String::from_utf8(challenge5::rcx(&key, &ciphertext)).unwrap();

    //println!("Key: {:?}\nPlaintext:\n----\n{}", key, plaintext);
    key
}

fn hamming_dist(left: &[u8], right: &[u8]) -> u32 {
    assert_eq!(left.len(), right.len());
    left
        .iter()
        .zip(
            right
            .iter()
            )
        .fold(0, |acc, (&l, &r)| acc + (l ^ r).count_ones() )
}

fn decode_b64_chunk(input: &[char]) -> Vec<u8> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // Build a 32-bit value out of (up to) 4 base64 characters
    let qw: u32 = input
        .iter()
        .map(|&c| alphabet.find(c))
        .map(|r| r.expect("Invalid base64 character!") as u8)
        .enumerate()
        .map(|(i, t)| (t as u32) << ((3-i)*6))
        .fold(0, |acc, x| acc+x);

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

pub fn b64_decode(input: &str) -> Vec<u8> {
    input
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(decode_b64_chunk)
        .flat_map(|c| c.into_iter())
        .collect::<Vec<u8>>()
}
