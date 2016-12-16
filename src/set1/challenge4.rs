/// Challenge 4
///
/// Detect single-character XOR
///
/// One of the 60-character strings in 4.txt has been encrypted by single-character XOR.
///
/// Find it.
///
/// (Your code from #3 should help.)

use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;
use std::str;
use std::cmp::Ordering::Greater;

use util::hex::FromHex;
use util::stat::score_byte_space;

pub fn challenge4() -> Result<String, String>
{
    let known_plaintext = "Now that the party is jumping\n";
    let filename = "4.txt";

    let mut results: Vec<(f32, u8, String)> = BufReader::new(File::open(filename).unwrap())
        .lines()
        .map(|line| line.unwrap())
        .map(|line| score_byte_space(&line.decode_hex()))
        .filter(|r| r.len() > 0)    // filter out lines w/ no valid outputs in the xor space
        .map(|r| r[0].clone())      // take the highest-scoring result from each line we search
        .filter(|ref r| r.0 < 0.05) // keep sufficiently high-scoring results across all lines
        .collect();
    results.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Greater));
    let winner = results[0].2.clone();

    if winner == known_plaintext {
        Ok(winner)
    } else {
        Err(format!("{} does not match expected {}", winner, known_plaintext))
    }
}
