/// Break repeating-key XOR
///
/// [ It is officially on, now.																		  ]
/// [																								  ]
/// [ This challenge isn't conceptually hard, but it involves actual error-prone coding. The other	  ]
/// [ challenges in this set are there to bring you up to speed. This one is there to qualify you. If ]
/// [ you can do this one, you're probably just fine up to Set 6.									  ]
///
/// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
///
/// Here's how:
///
/// 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
///
/// 2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming
///    distance is just the number of differing bits. The distance between:
///
///        this is a test
///
///    and
///
///        wokka wokka!!!
///
///    is 37. Make sure your code agrees before you proceed.
///
/// 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
///    and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
///
/// 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed
///    perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average
///    the distances.
///
/// 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
///
/// 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that
///    is the second byte of every block, and so on.
///
/// 7. Solve each block as if it was single-character XOR. You already have code to do this.
/// 8. For each block, the single-byte XOR key that produces the best looking histogram is the
///    repeating-key XOR key byte for that block. Put them together and you have the key.
///
/// This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR
/// ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more
/// people "know how" to break it than can actually break it, and a similar technique breaks
/// something much more important.
///
/// [ No, that's not a mistake.																		  ]
/// [																								  ]
/// [ We get more tech support questions for this challenge than any of the other ones. We promise,   ]
/// [ there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance ]
/// [ really is 37.																					  ]

use std::cmp::Ordering::Equal;
use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;

use util::stat::hamming_dist;
use util::base64::FromBase64;
use util::stat::score_byte_space;

pub fn challenge6() -> Result<String, String> {
    let filename = "6.txt";
    let unknown_key = "Terminator X: Bring the noise";

    let ciphertext = BufReader::new(File::open(filename).unwrap())
        .lines()
        .fold(String::new(), |acc, l| acc + &(l.unwrap()))
        .from_base64();
    //let ciphertext = b64_decode(&ciphertext[..]);

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
        .map(|row| score_byte_space(row))
        .collect();

    let key = String::from_utf8(
        rowscores
        .iter()
        .map(|r| r[0].1)
        .collect()
        ).unwrap();

    if key == unknown_key {
        Ok(key)
    } else {
        Err(format!("{} does not match expected {}", key, unknown_key))
    }
}
