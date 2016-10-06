// Challenge 13
//
// ECB cut-and-paste
//
// Write a k=v parsing routine, as if for a structured cookie. The routine should take:
//
// foo=bar&baz=qux&zap=zazzle
//
// ... and produce:
//
// {
//   foo: 'bar',
//   baz: 'qux',
//   zap: 'zazzle'
// }
//
// (you know, the object; I don't care if you convert it to JSON).
//
// Now write a function that encodes a user profile in that format, given an email address.
// You should have something like:
//
// profile_for("foo@bar.com")
//
// ... and it should produce:
//
// {
//     email: 'foo@bar.com',
//     uid: 10,
//     role: 'user'
// }
// ... encoded as:
//
// email=foo@bar.com&uid=10&role=user
//
// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat
// them, quote them, whatever you want to do, but don't let people set their email
// address to "foo@bar.com&role=admin".
//
// Now, two more easy functions. Generate a random AES key, then:
//
// A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
// B. Decrypt the encoded user profile and parse it.
//
// Using only the user input to profile_for() (as an oracle to generate "valid"
// ciphertexts) and the ciphertexts themselves, make a role=admin profile.

extern crate url;
extern crate crypto;

use std::cmp::min;
use std::collections::HashMap;
use self::url::percent_encoding::{percent_decode, percent_encode, USERINFO_ENCODE_SET};
use self::crypto::aessafe::AesSafe128Decryptor;
use self::crypto::symmetriccipher::BlockDecryptor;

use challenge9::pad_block;
use challenge11::ecb_encrypt;

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub uid: u32,
    pub role: String
}

impl User {
    pub fn encode(&self) -> String {
        let escaped_email: String = percent_encode(&self.email.as_bytes(), USERINFO_ENCODE_SET).collect();
        let escaped_role: String = percent_encode(&self.role.as_bytes(), USERINFO_ENCODE_SET).collect();
        format!("email={}&uid={}&role={}", escaped_email, self.uid, escaped_role)
    }

    pub fn decode(params: &str) -> User {
        let mut dict = HashMap::new();
        for param in params.split('&') {
             let kv = param.split('=').collect::<Vec<&str>>();
             if kv.len() == 2 {
                 dict.insert(kv[0].to_string(), kv[1].to_string());
             }
        }
        User {
            email: percent_decode(
                       dict.get("email").expect("no email param").as_bytes()
                   ).decode_utf8().unwrap().to_string(),
            uid: dict.get("uid").expect("no uid param").parse::<u32>().unwrap(),
            role: percent_decode(dict.get("role").expect("no role").clone().as_bytes()).decode_utf8().unwrap().to_string()
        }
    }
}

pub fn profile_for(email: &str) -> String {
    let uid = 10;
    let role = "user";
    User {
        email: String::from(email),
        uid: uid,
        role: String::from(role)
    }.encode()
}

pub fn ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let key = pad_block(key, 16, b'\x00');
    let decryptor = AesSafe128Decryptor::new(&(key.unwrap()));
    let mut output: Vec<u8> = Vec::with_capacity(ciphertext.len());

    for block in ciphertext.chunks(16) {
        let mut result = vec![0; 16];
        let block = pad_block(block, 16, b'\x00');
        decryptor.decrypt_block(block.unwrap().as_slice(), &mut result);
        output.append(&mut result);
    }
    output
}

pub fn encrypt_profile(email: &str, key: &[u8]) -> Vec<u8> {
    ecb_encrypt(profile_for(email).as_bytes(), key)
}

pub fn decrypt_profile(profile: &[u8], key: &[u8]) -> User {
    let string = String::from_utf8(ecb_decrypt(profile, &key)).unwrap();
    User::decode(&string)
}

pub fn fake_profile(key: &[u8], username: &str, domain: &str) -> Vec<u8> {

    //  email= {username} +{pad} %40 {domain} &uid=10&role=
    //    6      len()      {x}   3   len()       13

    let userpad: String = {
        let padlen = 16 - ((username.len()+6) % 16);
        if padlen > 0 {
            format!("+{}", String::from_utf8(vec![b'a'; padlen-1]).unwrap())
        } else { "".to_string() }
    };
    let left_head = format!("{}{}", username, userpad);

    let domainpad: String = {
        let padlen = 16 - ((domain.len()+16) % 16);
        if padlen > 0 {
            String::from_utf8(vec![b'a'; padlen]).unwrap()
        } else { "".to_string() }
    };
    let left_tail = format!("{}@{}", domainpad, domain);
    let email = format!("{}{}", left_head, left_tail);
    let num_blocks = (email.len()+22) / 16;

    let profile = profile_for(&email);
    let admin = "aaaaaaa@admin";
    let mut lb = encrypt_profile(&email,  key)[0..(16*num_blocks)].to_vec();
    let rb = encrypt_profile(admin, key)[16..32].to_vec();
    lb.extend(rb);
    lb
}
