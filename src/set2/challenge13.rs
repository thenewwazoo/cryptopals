/// Challenge 13
///
/// ECB cut-and-paste
///
/// Write a k=v parsing routine, as if for a structured cookie. The routine should take:
///
///     foo=bar&baz=qux&zap=zazzle
///
/// ... and produce:
///
///     {
///       foo: 'bar',
///       baz: 'qux',
///       zap: 'zazzle'
///     }
///
/// (you know, the object; I don't care if you convert it to JSON).
///
/// Now write a function that encodes a user profile in that format, given an email address.
/// You should have something like:
///
///     profile_for("foo@bar.com")
///
/// ... and it should produce:
///
///     {
///         email: 'foo@bar.com',
///         uid: 10,
///         role: 'user'
///     }
///
/// ... encoded as:
///
///     email=foo@bar.com&uid=10&role=user
///
/// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat
/// them, quote them, whatever you want to do, but don't let people set their email
/// address to "foo@bar.com&role=admin".
///
/// Now, two more easy functions. Generate a random AES key, then:
///
/// A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
/// B. Decrypt the encoded user profile and parse it.
///
/// Using only the user input to profile_for() (as an oracle to generate "valid"
/// ciphertexts) and the ciphertexts themselves, make a role=admin profile.

use std::collections::HashMap;

use util::{generate_key, pkcs7_pad};
use util::encryption::{ecb_encrypt, ecb_decrypt};

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub uid: u32,
    pub role: String,
}

impl User {
    pub fn encode(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }

    pub fn decode(params: &str) -> Result<User, String> {
        let mut dict = HashMap::new();
        for param in params.split('&') {
            let kv = param.split('=').collect::<Vec<&str>>();
            if kv.len() == 2 {
                match dict.insert(kv[0].to_string(), kv[1].to_string()) {
                    None => continue,
                    _ => return Err(format!("redundant param {} in {}", kv[0], params)),
                }
            } else {
                return Err(String::from(format!("params malformed: {}", params)));
            }
        }
        Ok(User {
            email: try!(dict.get("email").ok_or("Could not get email param")).clone().to_string(),
            uid: match try!(dict.get("uid").ok_or("Could not get uid param")).parse::<u32>() {
                Ok(u) => u,
                Err(e) => return Err(format!("uid not u32: {}", e)),
            },
            role: try!(dict.get("role").ok_or("Could not get role param")).clone().to_string(),
        })
    }
}

fn profile_for(email: &str) -> Result<String, String> {
    match User::decode(&format!("email={}&uid={}&role={}", email, 10, "user")) {
        Ok(u) => Ok(u.encode()),
        Err(e) => Err(format!("Could not build a profile for {}: {}", email, e)),
    }
}

fn encrypt_profile(profile: &str, key: &[u8]) -> Vec<u8> {
    ecb_encrypt(profile.as_bytes(), key)
}

fn decrypt_profile(profile: &[u8], key: &[u8]) -> Result<User, String> {
    let decrypted = match String::from_utf8(ecb_decrypt(profile, &key)) {
        Ok(s) => s,
        _ => return Err(String::from("could not build a string from decrypted profile")),
    };
    User::decode(&decrypted)
}

pub fn challenge13() -> Result<String, String> {
    // The goal here is to exploit the use of ECB so I can pick-and-choose what blocks
    // to use in order to construct a payload that will decrypt correctly.
    //
    // A typical encrypted profile consists of the following blocks:
    //
    //     email=cryptopals rulz@optimaltour .us&uid=10&role= ...
    //     0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF ...
    //
    // Ultimately, we need to construct a set of blocks with breaks in appropriate places.
    // We need the three above, plus one that looks like:
    //
    //     admin
    //     01234
    //
    // The data that precedes or succeeds these blocks doesn't matter, so long as the
    // blocks break on convenient boundaries, so we can pick and choose which block to use.
    //

    let key = generate_key(16);

    // Get the first two blocks that have my chosen email address:
    //     email=cryptopals rulz@optimaltour .us&uid=10&role= ...
    //     0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF ...
    //
    let first_two_blocks =
        encrypt_profile(&profile_for("cryptopalsrulz@optimaltour.us")?, &key)[..3 * 16].to_vec();

    // Now get a block that starts with 'admin' and looks like a properly-padded block:
    //     email=xxxxxxxxxx admin...........
    //     0123456789ABCDEF 0123456789ABCDEF
    //
    // where the '.' in the block are PKCS#7 padding.
    //
    let admin_input = String::from_utf8(pkcs7_pad("admin".as_bytes(), 16)?).unwrap();
    let final_block =
        encrypt_profile(&profile_for(&format!("xxxxxxxxxx{}", admin_input))?, &key)[16..32]
            .to_vec();

    let mut faked_profile: Vec<u8> = Vec::with_capacity(16 * 4 as usize);
    faked_profile.extend(first_two_blocks.into_iter());
    faked_profile.extend(final_block.into_iter());

    Ok(decrypt_profile(&faked_profile, &key)?.encode())

}
