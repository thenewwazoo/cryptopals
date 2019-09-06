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
    use arse::encode::base64::ToBase64;
    use arse::encode::hex::TryFromHex;

    const HEX_INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const B64_OUTPUT: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(HEX_INPUT.try_from_hex().unwrap().to_base64(), B64_OUTPUT);
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
    use arse::encode::hex::{ToHex, TryFromHex};
    use arse::transform::TryFixedXor;

    const HEX_INPUT: &str = "1c0111001f010100061a024b53535009181c";
    const HEX_KEY: &str = "686974207468652062756c6c277320657965";

    const OUTPUT: &str = "746865206b696420646f6e277420706c6179";

    let input_bytes = HEX_INPUT.try_from_hex().unwrap();
    let key_bytes = HEX_KEY.try_from_hex().unwrap();

    let result = &input_bytes
        .as_slice()
        .try_fixed_xor(key_bytes.as_slice())
        .unwrap()
        .to_hex();

    assert_eq!(result, OUTPUT);
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
    use arse::encode::hex::TryFromHex;
    use arse::stat::Histogram;
    use arse::transform::TryFixedXor;
    use arse::xor_cipher::score_byte_decode;
    use std::u8;

    const CIPHERTEXT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let english = Histogram::english();

    let ctext_bytes = CIPHERTEXT.try_from_hex().unwrap();

    use arse::xor_cipher::find_best_in;

    let best_byte = find_best_in(0u8..u8::MAX, |&test_byte| {
        score_byte_decode(test_byte, &ctext_bytes, &english).ok()
    })
    .unwrap();
    let key = vec![best_byte; ctext_bytes.len()];
    let cleartext = &ctext_bytes
        .as_slice()
        .try_fixed_xor(key.as_slice())
        .unwrap();
    let cleartext = String::from_utf8_lossy(cleartext);
    println!("Using value {:X}, decoded string: {}", best_byte, cleartext);
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
    use arse::encode::hex::TryFromHex;
    use arse::stat::Histogram;
    use arse::transform::TryFixedXor;
    use arse::xor_cipher::score_byte_decode;
    use std::{f64, u8};

    let english = Histogram::english();

    let search_result: Option<(String, f64)> =
        include_str!("data/4.txt")
            .lines()
            .fold(None, |best_score, line| {
                let ctext_bytes = line.try_from_hex().unwrap();

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
    use arse::encode::hex::ToHex;
    use arse::transform::XorWith;

    const INPUT: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const OUTPUT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const KEY: &str = "ICE";

    let result = INPUT.as_bytes().xor_with(KEY.as_bytes()).to_hex();

    assert_eq!(
        OUTPUT, result,
        "Result {} does not match {}",
        result, OUTPUT
    );
}

/// Challenge 6
///
/// Break repeating-key XOR
///
/// It is officially on, now.
///
/// This challenge isn't conceptually hard, but it involves actual error-prone coding. The other
/// challenges in this set are there to bring you up to speed. This one is there to qualify you. If
/// you can do this one, you're probably just fine up to Set 6.
///
/// [There's a file here](data/6.txt). It's been base64'd after being encrypted with repeating-key XOR.
///
/// Decrypt it.
///
/// Here's how:
///
/// 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
///
/// 2. Write a function to compute the edit distance/Hamming distance between two strings. The
///    Hamming distance is just the number of differing bits. The distance between:
///
/// > this is a test
///
/// and
///
/// > wokka wokka!!!
///
/// is 37. Make sure your code agrees before you proceed.
///
/// 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of
///    bytes, and find the edit distance between them. Normalize this result by dividing by
///    KEYSIZE.
///
/// 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could
///    proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2
///    and average the distances.
///
/// 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
///
/// 6. Now transpose the blocks: make a block that is the first byte of every block, and a block
///    that is the second byte of every block, and so on.
///
/// 7. Solve each block as if it was single-character XOR. You already have code to do this.
///
/// 8. For each block, the single-byte XOR key that produces the best looking histogram is the
///    repeating-key XOR key byte for that block. Put them together and you have the key.
///
/// This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR
/// ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more
/// people "know how" to break it than can actually break it, and a similar technique breaks
/// something much more important.
///
/// > No, that's not a mistake.
/// >
/// > We get more tech support questions for this challenge than any of the other ones. We promise,
/// > there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance
/// > really is 37.
#[test]
fn challenge6() {
    use arse::encode::base64::TryFromBase64;
    use arse::stat::Histogram;
    use arse::transform::XorWith;
    use arse::xor_cipher::{find_best_in, score_byte_decode};
    use hamming::distance;
    use std::{f64, u8};

    let english = Histogram::english();

    let mut ciphertext = include_str!("data/6.txt").to_string();
    ciphertext.retain(|c| !c.is_whitespace());

    let ctxt_bytes = ciphertext.try_from_base64().unwrap();

    // initial sanity test of hamming distance function (you can't trust open-source code,
    // y'know).
    assert_eq!(
        distance("wokka wokka!!!".as_bytes(), "this is a test".as_bytes()),
        37
    );

    let best_keysize = find_best_in(2..45, |&keylen| {
        Some(
            ctxt_bytes
                .chunks(keylen)
                .zip(ctxt_bytes[keylen..].chunks(keylen))
                .fold(0.0, |sum, (pre, post)| {
                    if pre.len() == post.len() {
                        sum + (distance(pre, post) as f64 / keylen as f64)
                    } else {
                        sum
                    }
                })
                / ((ctxt_bytes.len() / keylen) as f64),
        )
    })
    .unwrap();

    assert!(best_keysize != 0, "Did not find a useful key size");

    let mut buffers: Vec<Vec<u8>> = vec![Vec::new(); best_keysize];
    for (i, &b) in ctxt_bytes.iter().enumerate() {
        buffers[i % best_keysize].push(b);
    }

    let key = buffers.iter().fold(Vec::new(), |mut acc, buffer| {
        acc.push(
            find_best_in(0u8..u8::MAX, |&test_byte| {
                score_byte_decode(test_byte, &buffer, &english).ok()
            })
            .unwrap(),
        );
        acc
    });

    // value determined experimentally and validated manually :)
    assert_eq!(key, b"Terminator X: Bring the noise", "bad key");

    let result = &ctxt_bytes.xor_with(&key);
    let _result = String::from_utf8_lossy(result);
    //print!("{}", result);
}

/// AES in ECB mode
///
/// The Base64-encoded content in [this file](data/7.txt) has been encrypted via AES-128 in ECB
/// mode under the key
///
/// `YELLOW SUBMARINE`
///
/// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because
/// it's exactly 16 bytes long, and now you do too).
///
/// Decrypt it. You know the key, after all.
///
/// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
///
/// > Do this with code.
/// >
/// > You can obviously decrypt this using the OpenSSL command-line tool,
/// > but we're having you get > ECB working in code for a reason. You'll need it a lot later on, and
/// > not just for attacking > ECB.
#[test]
fn challenge7() {
    use aes::Aes128;
    use arse::encode::base64::TryFromBase64;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Ecb};

    const KEY: &[u8] = b"YELLOW SUBMARINE";

    let mut ciphertext = include_str!("data/7.txt").to_string();
    ciphertext.retain(|c| !c.is_whitespace());
    let ciphertext = ciphertext.try_from_base64().unwrap();

    type Aes128Ecb = Ecb<Aes128, Pkcs7>;

    let cipher = Aes128Ecb::new_var(KEY, Default::default()).unwrap();

    let decrypted = cipher.decrypt_vec(&ciphertext).unwrap();
    let _decrypted = String::from_utf8_lossy(&decrypted).to_owned();
}
