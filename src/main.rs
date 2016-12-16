
// Welcome to my implementation of the solutions to the Cryptopals challenges! Do stay a while,
// won't you?

extern crate cryptopals;

use cryptopals::util::base64::FromBase64;

fn check_success(challenge_num: u32, result: Result<String, String>)
{
    match result {
        Ok(output) => println!(
            "Challenge {} okay! Got delicious output:\n{}\n----",
            challenge_num,
            output
            ),
        Err(errmsg) => panic!("Challenge {} returned an error!\n{}", challenge_num, errmsg)
    }
}

fn main()
{
    check_success(1, match cryptopals::challenge1() {
        Ok(output) => Result::Ok(String::from_utf8(output.from_base64()).unwrap()),
        Err(errstr) => Err(errstr)
    });
    check_success(2, match cryptopals::challenge2() {
        Ok(output) => Result::Ok(String::from_utf8(output).unwrap()),
        Err(errstr) => Err(errstr)
    });
    check_success(3, cryptopals::challenge3());
    check_success(4, cryptopals::challenge4());
    check_success(5, cryptopals::challenge5());
    check_success(6, cryptopals::challenge6());
    check_success(7, cryptopals::challenge7());
    check_success(8, cryptopals::challenge8());
    check_success(9, cryptopals::challenge9());
    check_success(10, cryptopals::challenge10());
    check_success(11, cryptopals::challenge11());
    check_success(12, cryptopals::challenge12());
    check_success(13, cryptopals::challenge13());
}
