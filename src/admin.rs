use db;
use jwt;
use models;
use auth_2fa;

use diesel::prelude::*;
use std::collections::HashMap;
use rocket_contrib::Template;



#[get("/admin")]
fn index(token: jwt::UserRolesToken) -> Option<Template> {
    if !token.has_role("admin") {
        return None;
    }

    let mut context = HashMap::new();
    context.insert("message", "Congrats, you're an admin.");
    Some(Template::render("admin/index", &context))
}

#[get("/admin/user")]
fn user(token: jwt::UserRolesToken) -> Option<Template> {
    if !token.has_role("admin") {
        return None;
    }

    use schema::users::dsl::*;
    let connection = db::establish_connection();
    let user = users.filter(username.eq(&token.user))
        .first::<models::User>(&connection)
        .expect(&format!("Failed to retrieve {}", token.user));

    let mut context = HashMap::new();
    context.insert("user",
                   vec![user.username, format!("{:?}", user.user_roles)].join(", "));

    Some(Template::render("admin/console", &context))
}

#[get("/admin/qr")]
fn qr(token: jwt::UserRolesToken) -> Option<Template> {
    if !token.has_role("admin") {
        return None;
    }

    use schema::users::dsl::*;
    let connection = db::establish_connection();
    let user = users.filter(username.eq(&token.user)).first::<models::User>(&connection).unwrap();

    let mut context = HashMap::new();
    context.insert("username", token.user.clone());

    if user.auth_token.is_some() {
        context.insert("qr_image_uri",
                       auth_2fa::qr_image_uri(user.auth_token.unwrap(), user.username));
    }

    Some(Template::render("admin/qr", &context))
}
