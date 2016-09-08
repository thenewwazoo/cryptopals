
extern crate data_encoding;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use self::data_encoding::base64;

mod challenge1;
mod challenge2;
mod challenge3;
mod challenge4;
mod challenge5;
mod challenge6;
mod challenge7;
mod challenge8;
mod challenge9;
mod challenge10;

fn main() {

    // Challenge 1
    assert_eq!(
        challenge1::b64_encode(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    println!("Challenge 1 okay");

    // Challenge 2
    assert_eq!(
        challenge2::fixed_xor(
            &challenge1::hex_decode("1c0111001f010100061a024b53535009181c"),
            &challenge1::hex_decode("686974207468652062756c6c277320657965")),
        challenge1::hex_decode("746865206b696420646f6e277420706c6179"));
    println!("Challenge 2 okay");

    // Challenge 3
    assert_eq!(
        challenge3::decrypt_message("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"),
        "Cooking MC's like a pound of bacon");
    println!("Challenge 3 okay");

    // Challenge 4
    assert!(challenge4::do_find_ciphertext("4.txt", "Now that the party is jumping\n"));
    println!("Challenge 4 okay");

    // Challenge 5
    assert_eq!(
        challenge5::hex_encode(
            challenge5::rcx(
                "ICE".as_bytes(),
                "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes()
            ).as_slice()
        ),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
    println!("Challenge 5 okay");

    // Challenge 6
    assert_eq!(String::from_utf8(challenge6::decipher_text("6.txt")).unwrap(), "Terminator X: Bring the noise");
    println!("Challenge 6 okay");

    // Challenge 7
    let c7score = challenge3::score_attempt(&String::from_utf8(challenge7::decrypt_file("7.txt", "YELLOW SUBMARINE".as_bytes())).unwrap());
    assert!(c7score < 0.05);
    println!("Challenge 7 okay");

    // Challenge 8
    assert_eq!("d8806197", &challenge8::detect_ecb_line("8.txt").expect("No line detected as ECB")[..8]);
    println!("Challenge 8 okay");

    assert_eq!(
        challenge9::do_challenge(),
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec()
        );
    println!("Challenge 9 okay");

    assert_eq!(
        BufReader::new(File::open("10.txt").unwrap())
        .lines()
        .fold(String::new(), |acc, l| acc + &(l.unwrap()))
        .as_bytes()
        .to_vec(),
        base64::encode(
            challenge10::cbc_encrypt(
                challenge10::cbc_decrypt_file("10.txt", "YELLOW SUBMARINE".as_bytes(), &[0 as u8; 16]).as_slice(),
                "YELLOW SUBMARINE".as_bytes(),
                &[0 as u8; 16]
                ).as_slice()
            ).as_bytes()
        )
    println!("Challenge 10 okay");


}
