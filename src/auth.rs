use db;
use jwt;
use models;
use auth_2fa;
use diesel::prelude::*;

use rocket::request::Form;
use rocket::response::NamedFile;
use rocket::response::Redirect;
use rocket::http::{Cookie, Cookies};
use rocket_contrib::Template;
use std::collections::HashMap;

use std::io;
use rand::os::OsRng;
use rand::Rng;
use argon2rs::verifier::Encoded;
use data_encoding::base32;

use std::thread;
use std::time::Duration;
const RATE_LIMIT: u64 = 500; // ms



#[derive(FromForm)]
struct Login {
    username: String,
    password: String,
    auth_code: Option<String>,
}

#[post("/login", data="<login_form>")]
fn login(cookies: &Cookies, login_form: Form<Login>) -> Redirect {
    use schema::users::dsl::*;

    let login = login_form.get();
    let connection = db::establish_connection();

    let user = match users.filter(username.eq(&login.username))
        .first::<models::User>(&connection) {
        Ok(u) => u,
        Err(_) => return Redirect::to("/login"),
    };

    if user.auth_token.is_some() {
        let auth_code = match login.auth_code.clone() {
            Some(code) => code,
            None => return Redirect::to("/login"),
        };

        if !auth_2fa::verify(user.auth_token.unwrap(), auth_code) {
            thread::sleep(Duration::from_millis(RATE_LIMIT));
            return Redirect::to("/login");
        }
    }

    let hash = user.pw_hash.into_bytes();

    // Argon2 password verifier
    let db_hash = Encoded::from_u8(&hash).expect("Failed to read password hash");
    if !db_hash.verify(login.password.as_ref()) {
        thread::sleep(Duration::from_millis(RATE_LIMIT));
        return Redirect::to("/login");
    }

    // Add JWT to cookies
    cookies.add(Cookie::new("jwt".into(), jwt::generate(user.username, user.user_roles)));

    Redirect::to("/")
}

#[get("/login")]
fn login_page() -> io::Result<NamedFile> {
    NamedFile::open("static/login.html")
}

#[post("/logout")]
fn logout(cookies: &Cookies) -> Redirect {
    cookies.remove("jwt");
    Redirect::to("/")
}



#[derive(FromForm)]
struct Create {
    username: String,
    password: String,
    password_confirm: String,
    auth_key: String,
    auth_code: String,
}

#[post("/create", data="<create_form>")]
fn create_account(create_form: Form<Create>) -> &'static str {
    let form = create_form.get();

    // I tried using Option<String> for this, but apparently an HTML form
    // defaults these to Some("")
    if form.username.is_empty() || form.password.is_empty() || form.password_confirm.is_empty() {
        return "Please complete the form";
    }

    if form.password.len() < 8 {
        return "Please use a stronger password.";
    }

    if form.password != form.password_confirm {
        return "Passwords entered do not match";
    }

    // If the user entered something in the code field, check if it verifies
    // against the token used for the qrcode. If so, enable 2FA for that account
    if !form.auth_code.is_empty() &&
       !auth_2fa::verify(form.auth_key.clone(), form.auth_code.clone()) {
        return "You entered an incorrect 2FA code";
    }

    use schema::users::dsl::*;
    let connection = db::establish_connection();

    // is_ok() is not okay :)
    if users.filter(username.eq(&form.username))
        .first::<models::User>(&connection)
        .is_ok() {
        return "A user by that name already exists";
    };


    // Argon2i crypt()-style hash string
    let pass_hash = {
        let mut salt = vec![0u8; 16];
        {
            let mut rng = OsRng::new().unwrap();
            rng.fill_bytes(&mut salt);
        }

        let hash = Encoded::default2i(form.password.clone().as_ref(), &salt, b"", b"").to_u8();

        String::from_utf8(hash).unwrap()
    };

    let new_user = models::User {
        username: form.username.clone(),
        pw_hash: pass_hash,
        user_roles: vec!["user".to_string()],
        auth_token: if !form.auth_code.is_empty() {
            Some(form.auth_key.clone())
        } else {
            None
        },
    };

    use schema::users;
    use diesel::query_builder::functions::insert;
    insert(&new_user)
        .into(users::table)
        .get_result::<models::User>(&connection)
        .expect("Error saving new post");


    "User created!"
}

#[get("/create")]
fn create_page() -> Template {
    let mut key = vec![0u8; 16];
    {
        let mut rng = OsRng::new().unwrap();
        rng.fill_bytes(&mut key);
    }

    // Annoyingly this applies a ton of padding but I didn't wanna have both
    // base32 and base64 packages
    let auth_key = base32::encode(&key);

    let mut context = HashMap::new();
    context.insert("auth_key", auth_key.clone());
    //context.insert("qr_image_uri", auth_2fa::qr_image_uri(auth_key));

    Template::render("create", &context)
}
