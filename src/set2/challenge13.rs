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

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub uid: u32,
    pub role: String
}

impl User {
    pub fn encode(&self) -> String{
        format!("email={}&uid={}&role=role", self.email, self.uid, self.role)
    }

    pub fn decode(params: &str) -> Result<User, String> {
        let mut dict = HashMap::new();
        for param in params.split('&') {
             let kv = param.split('=').collect::<Vec<&str>>();
             if kv.len() == 2 {
                 match dict.insert(kv[0].to_string(), kv[1].to_string()) {
                     None => continue,
                     _ => return Err(format!("redundant {} param", kv[0])),
                 }
             } else {
                 return Err("params malformed")
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
