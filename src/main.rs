#![feature(plugin)]
#![plugin(rocket_codegen)]
#![feature(custom_derive)]

use std::collections::HashMap;

extern crate rocket;
use rocket::response::Redirect;
use rocket::http::Cookies;

extern crate rocket_contrib;
use rocket_contrib::Template;

extern crate dotenv;
use dotenv::dotenv;



#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_codegen;
pub mod db;
pub mod schema;
pub mod models;

extern crate time;
extern crate rustc_serialize;
extern crate jsonwebtoken;
pub mod jwt;

extern crate argon2rs;
extern crate rand;
pub mod auth;
pub mod admin;

extern crate libreauth;
extern crate image;
extern crate qrcode;
extern crate data_encoding;
pub mod auth_2fa;



// LAUNCHER
//      Index page to redirect user to login, or render their name
//      Start application
//
#[get("/")]
fn index(cookies: &Cookies) -> Result<Template, Redirect> {
    let token = match cookies.find("jwt").map(|cookie| cookie.value) {
        Some(jwt) => jwt,
        None => return Err(Redirect::to("/login")),
    };

    let token_data = match jwt::extract(token) {
        Ok(data) => data.claims,
        Err(_) => return Err(Redirect::to("/login")),
    };

    let mut context = HashMap::new();
    context.insert("name", token_data.user.clone());

    if token_data.has_role("admin") {
        context.insert("admin", "true".to_string());
    }

    Ok(Template::render("index", &context))
}

fn main() {
    rocket::ignite()
        .mount("/",
               routes![index,
                       auth::login,
                       auth::login_page,
                       auth::logout,
                       auth::create_account,
                       auth::create_page,
                       auth_2fa::qr_image_uri,
                       admin::index,
                       admin::user,
                       admin::qr])
        .launch();
}
