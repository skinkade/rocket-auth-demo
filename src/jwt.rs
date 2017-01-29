// JSON WEB TOKEN
//      Our `users` table contain a text array of a given user's roles
//      When we verify a user, we give them a signed token confirming their
//          identity and roles, so we don't need to handle sessions
//
use jsonwebtoken::{encode, decode, Header, Algorithm, errors, TokenData};
use time;

// head -c16 /dev/urandom > secret.key
static KEY: &'static [u8; 16] = include_bytes!("../secret.key");
static ONE_WEEK: i64 = 60 * 60 * 24 * 7;


#[derive(Debug, RustcEncodable, RustcDecodable)]
pub struct UserRolesToken {
    // issued at
    iat: i64,
    // expiration
    exp: i64,
    pub user: String,
    pub roles: Vec<String>,
}

// only has_role() is used in this demo
impl UserRolesToken {
    pub fn is_expired(&self) -> bool {
        let now = time::get_time().sec;
        now >= self.exp
    }

    pub fn is_claimed_user(&self, claimed_user: String) -> bool {
        self.user == claimed_user
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }
}


pub fn generate(user: String, roles: Vec<String>) -> String {
    let now = time::get_time().sec;
    let payload = UserRolesToken {
        iat: now,
        exp: now + ONE_WEEK,
        user: user,
        roles: roles,
    };

    encode(Header::default(), &payload, KEY).unwrap()
}

pub fn extract(token: String) -> Result<TokenData<UserRolesToken>, errors::Error> {
    decode::<UserRolesToken>(&token, KEY, Algorithm::HS256)
}
