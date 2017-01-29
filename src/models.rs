use schema::users;

#[derive(Queryable, Insertable)]
#[table_name="users"]
pub struct User {
    pub username: String,
    pub pw_hash: String,
    pub user_roles: Vec<String>,
    pub auth_token: Option<String>,
}
