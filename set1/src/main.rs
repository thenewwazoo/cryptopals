
mod challenge1;
mod challenge2;
mod challenge3;
mod challenge4;

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

}
