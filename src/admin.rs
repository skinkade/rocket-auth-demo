use db;
use jwt;
use models;
use auth_2fa;

use diesel::prelude::*;
use std::collections::HashMap;
use rocket::http::Cookies;
use rocket_contrib::Template;



// ADMIN
//      By using a dynamic path in our main handler, we can use a single block
//      of cookie-check code to verify if the user has the admin role. Then,
//      pseudo-redirect the request to another function
//
//      By returning 404 instead of 403, we don't reveal that these pages exist
//      ... also trying to use Result and returning Err(Status) resulted in 500
//
#[get("/admin/<path>")]
fn handler(cookies: &Cookies, path: &str) -> Option<Template> {
    let token = match cookies.find("jwt").map(|cookie| cookie.value) {
        Some(jwt) => jwt,
        _ => return None,
    };

    let token_data = match jwt::extract(token) {
        Ok(data) => data.claims,
        Err(_) => return None,
    };

    if !token_data.has_role("admin") {
        return None;
    }

    match path {
        "index" => Some(admin_index()),
        "user" => Some(display_user(token_data.user)),
        "qr" => Some(display_2fa_qr(token_data.user)),
        _ => None,
    }
}

fn admin_index() -> Template {
    let mut context = HashMap::new();
    context.insert("message", "Congrats, you're an admin.");
    Template::render("admin/index", &context)
}

fn display_user(user: String) -> Template {
    use schema::users::dsl::*;
    let connection = db::establish_connection();
    let user = users.filter(username.eq(&user))
        .first::<models::User>(&connection)
        .expect(&format!("Failed to retrieve {}", user));

    let mut context = HashMap::new();
    context.insert("user",
                   vec![user.username, format!("{:?}", user.user_roles)].join(", "));

    Template::render("admin/console", &context)
}

fn display_2fa_qr(name: String) -> Template {
    use schema::users::dsl::*;
    let connection = db::establish_connection();
    let user = users.filter(username.eq(&name)).first::<models::User>(&connection).unwrap();

    let mut context = HashMap::new();
    context.insert("username", name.clone());

    if user.auth_token.is_some() {
        context.insert("qr_image_uri",
                       auth_2fa::qr_image_uri(user.auth_token.unwrap(), user.username));
    }

    Template::render("admin/qr", &context)
}
