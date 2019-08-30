/// # Convert hex to base64
///
/// The string:
///
/// `49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`
///
/// Should produce:
///
/// `SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`
///
/// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
///
/// > Cryptopals Rule
/// >
/// > Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
#[test]
fn challenge1() {
    use arse::transform::{base64_encode, hex_decode};

    const HEX_INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const B64_OUTPUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes_from_hex = hex_decode(HEX_INPUT).unwrap();
    let b64_string = base64_encode(&bytes_from_hex);
    assert_eq!(&b64_string, B64_OUTPUT);
}

/// # Fixed XOR
///
/// Write a function that takes two equal-length buffers and produces their XOR combination.
///
/// If your function works properly, then when you feed it the string:
///
/// `1c0111001f010100061a024b53535009181c`
///
/// ... after hex decoding, and when XOR'd against:
///
/// `686974207468652062756c6c277320657965`
///
/// ... should produce:
///
/// `746865206b696420646f6e277420706c6179`
#[test]
fn challenge2() {
    use arse::transform::TryFixedXor;
    use arse::transform::{hex_decode, hex_encode};

    const HEX_INPUT: &str = "1c0111001f010100061a024b53535009181c";
    const HEX_KEY: &str = "686974207468652062756c6c277320657965";

    const OUTPUT: &str = "746865206b696420646f6e277420706c6179";

    let input_bytes = hex_decode(HEX_INPUT).unwrap();
    let key_bytes = hex_decode(HEX_KEY).unwrap();

    let result = hex_encode(
        &input_bytes
            .as_slice()
            .try_fixed_xor(key_bytes.as_slice())
            .unwrap(),
    );

    assert_eq!(&result, OUTPUT);
}

/// # Single-byte XOR cipher
///
/// The hex encoded string:
///
/// `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
///
/// ... has been XOR'd against a single character. Find the key, decrypt the message.
///
/// You can do this by hand. But don't: write code to do it for you.
///
/// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a
/// good metric. Evaluate each output and choose the one with the best score.
///
/// > Achievement Unlocked
/// >
/// > You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
#[test]
fn challenge3() {
    use arse::stat::Histogram;
    use arse::transform::{hex_decode, TryFixedXor};
    use arse::xor_cipher::score_byte_decode;
    use std::collections::HashMap;
    use std::{f32, u8};

    const CIPHERTEXT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let english: Histogram<char> = Histogram(
        [
            ('e', 0.12702),
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
            //('\u{0}', f32::MAX),
        ]
        .into_iter()
        .cloned()
        .collect::<HashMap<char, f32>>(),
    );

    let ctext_bytes = hex_decode(CIPHERTEXT).unwrap();

    match (0u8..u8::MAX).fold(None, |best_score: Option<(u8, f32)>, test_byte: u8| {
        match (
            score_byte_decode(test_byte, &ctext_bytes, &english),
            best_score,
        ) {
            // compare this new score with a prior best score
            (Ok(score), Some((_, best_score_val))) => {
                if score < best_score_val {
                    Some((test_byte, score))
                } else {
                    best_score
                }
            }
            // we haven't found a reasonable score yet, so this is the best
            (Ok(score), None) => Some((test_byte, score)),
            // We couldn't score this one, so take whatever we've had before (even if it's None)
            (Err(_), _) => best_score,
        }
    }) {
        Some((b, score)) => {
            let key = vec![b; ctext_bytes.len()];
            let cleartext = String::from_utf8_lossy(
                &ctext_bytes
                    .as_slice()
                    .try_fixed_xor(key.as_slice())
                    .unwrap(),
            )
            .into_owned();
            println!(
                "Using value {:X} with score {}, decoded string: {}",
                b, score, cleartext
            );
            assert!(true)
        }
        None => assert!(false, "could not find a decodable string"),
    }
}

/// Detect single-character XOR
///
/// One of the 60-character strings in [this file](data/4.txt) has been encrypted by single-character XOR.
///
/// Find it.
///
/// (Your code from #3 should help.)
#[test]
fn challenge4() {
    use arse::stat::Histogram;
    use arse::transform::{hex_decode, TryFixedXor};
    use arse::xor_cipher::score_byte_decode;
    use std::collections::HashMap;
    use std::{f32, u8};

    let english: Histogram<char> = Histogram(
        [
            ('e', 0.12702),
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
        ]
        .into_iter()
        .cloned()
        .collect::<HashMap<char, f32>>(),
    );

    let search_result: Option<(String, f32)> =
        include_str!("data/4.txt")
            .lines()
            .fold(None, |best_score, line| {
                let ctext_bytes = hex_decode(line).unwrap();

                match (0u8..u8::MAX).fold(None, |best_score, test_byte| {
                    let score = score_byte_decode(test_byte, &ctext_bytes, &english);
                    match score {
                        Ok(score) => {
                            match best_score {
                                None => Some((test_byte, score)), // this is the first, and thus best, score we've found
                                Some((_, best_score_val)) => {
                                    if score < best_score_val {
                                        Some((test_byte, score))
                                    } else {
                                        best_score
                                    }
                                }
                            }
                        }
                        Err(_) => best_score,
                    }
                }) {
                    Some((best_byte, line_score)) => {
                        let key = vec![best_byte; ctext_bytes.len()];
                        let cleartext = String::from_utf8_lossy(
                            &ctext_bytes
                                .as_slice()
                                .try_fixed_xor(key.as_slice())
                                .unwrap(),
                        )
                        .into_owned();
                        match best_score {
                            None => Some((cleartext, line_score)),
                            Some((_, best_line_score)) => {
                                if line_score < best_line_score {
                                    Some((cleartext, line_score))
                                } else {
                                    best_score
                                }
                            }
                        }
                    }
                    None => best_score,
                }
            });
    match search_result {
        Some((cleartext, best_line_score)) => {
            println!(
                "cleartext [{}] found with score {}",
                cleartext, best_line_score
            );
            assert!(true)
        }
        None => assert!(false, "Could not decode any line whatsoever"),
    };
}


/// Challenge 5
///
/// Implement repeating-key XOR
///
/// Here is the opening stanza of an important work of the English language:
///
/// > Burning 'em, if you ain't quick and nimble
/// > I go crazy when I hear a cymbal
///
/// Encrypt it, under the key "ICE", using repeating-key XOR.
///
/// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of
/// plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and
/// so on.
///
/// It should come out to:
///
/// > `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272`
/// > `a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
///
/// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your
/// password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with
/// this.
#[test]
fn challenge5() {
    const INPUT: &str = "Burning 'em, if you ain't quick and nimble"
                        "I go crazy when I hear a cymbal";
    const OUTPUT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                         "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &str = "ICE";
}
