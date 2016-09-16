// Challenge 12
//
// Byte-at-a-time ECB decryption (Simple)
//
// Copy your oracle function to a new function that encrypts buffers under ECB mode using a
// consistent but unknown key (for instance, assign a single random key, once, to a global
// variable).
//
// Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the
// following string:
//
// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
// YnkK
//
// Base64 decode the string before appending it. Do not base64 decode the string by hand; make your
// code do it. The point is that you don't know its contents.
//
// What you have now is a function that produces:
//
// AES-128-ECB(your-string || unknown-string, random-key)
//
// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
//
// Here's roughly how:
//
// 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
//    then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this
//    step anyway.
// 2. Detect that the function is using ECB. You already know, but do this step anyways.
// 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the
//    block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in
//    that last byte position.
// 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for
//    instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
// 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've
//    now discovered the first byte of unknown-string.
// 6. Repeat for the next byte.

use data_encoding::base64;
use std::collections::HashMap;

use challenge8::detect_ecb;
use challenge11;
use std::u8;

fn appended_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {

    let mut concatenated: Vec<u8> = plaintext.to_vec();
    concatenated.extend(base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".as_bytes()).unwrap().iter());

    challenge11::ecb_encrypt(&concatenated, key)
}

fn find_blocksz(enc: fn(&[u8], &[u8]) -> Vec<u8>) -> Result<usize, String> {
    let key = challenge11::generate_key(16);
    let mut detlens = Vec::new();
    for l in 1..128 {
        let input = vec![b'A'; l];
        detlens.push(enc(&input, &key).len());
        detlens.dedup();
    }
    let mut sizes = detlens.windows(2).map(|w| w[1]-w[0]).collect::<Vec<usize>>();
    sizes.dedup();

    match sizes.len() {
        1 => Ok(sizes[0]),
        _ => Err(String::from("Could not converge on a block size"))
    }
}

pub fn do_12() -> String {
    let block_size = find_blocksz(appended_encrypt).expect("Could not find a block size!");
    let key = challenge11::generate_key(block_size);
    let is_ecb = detect_ecb(&appended_encrypt(&vec![b'A'; block_size*8], &key));
    if ! is_ecb { println!("encryption does not use ecb"); }
    let mut foundbytes = Vec::new();

    let unk_str_blocks = appended_encrypt(&[], &key).len() / block_size;
    for which_block in 0..unk_str_blocks {
        for _ in 0..block_size {

            let start_idx = which_block * block_size;
            let mut one_short = vec![b'A'; block_size-1 - (foundbytes.len() % block_size)];
            let block = appended_encrypt(&one_short, &key)[start_idx..start_idx + block_size].to_vec();
            one_short.extend(&foundbytes);
            let mut byte_dict: HashMap<Vec<u8>, u8> = HashMap::new();
            for b in u8::MIN..u8::MAX {
                let mut inblock = one_short.clone();
                inblock.push(b as u8);
                byte_dict.insert(appended_encrypt(&inblock, &key)[start_idx..start_idx+block_size].to_vec(), b as u8);
            }

            let foundbyte = *byte_dict.get(&block).expect("Could not find byte");
            foundbytes.push(foundbyte);
        }
    }
    let foundbytes = foundbytes.into_iter().filter(|&b| b != 0 ).collect();
    String::from_utf8(foundbytes).unwrap()
}