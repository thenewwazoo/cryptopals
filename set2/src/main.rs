
mod challenge9;

fn main() {

    assert_eq!(
        challenge9::do_challenge9(),
        "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec()
        );
    println!("Challenge 9 okay");

}
