#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_contrib;

extern crate bcrypt;
extern crate rocket_client_addr;

use rocket::request::Form;
use rocket::response::{NamedFile, Redirect};
use rocket_client_addr::ClientAddr;
use std::io;

#[macro_use]
extern crate diesel;

use diesel::prelude::*;

table! {
    users (username) {
        username -> Text,
        password -> Text,
    }
}

#[derive(Queryable, Insertable, FromForm)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[database("user_db")]
struct UsersDbConn(diesel::SqliteConnection);

#[get("/")]
fn index(client_addr: ClientAddr) -> io::Result<NamedFile> {
    let addr = client_addr.get_ipv4().unwrap();
    eprintln!("{} is asking for WiFi.", addr);
    NamedFile::open("static/index.html")
}

#[post("/login?<is_register>", data = "<user>")]
fn login(
    user: Form<User>,
    is_register: Option<bool>,
    client_addr: ClientAddr,
    db_conn: UsersDbConn,
) -> Redirect {
    use self::users;
    use self::users::dsl::*;

    let is_register = is_register.unwrap_or_default();
    let addr = client_addr.get_ipv4().unwrap();
    eprintln!("is_register = {} addr = {}", is_register, addr);
    eprintln!("name: {}, password: {}", user.username, user.password);
    let results = users
        .filter(username.eq(&user.username))
        .limit(1)
        .load::<User>(&*db_conn)
        .expect("Error loading users");
    assert!(results.len() <= 1);

    if !is_register {
        if results.len() == 0 {
            return Redirect::to("/");
        }
        let result = bcrypt::verify(&user.password, &results[0].password).unwrap_or(false);

        if !result {
            return Redirect::to("/");
        }
    } else {
        if results.len() == 1 {
            return Redirect::to("/");
        }
        let hash = bcrypt::hash(&user.password, 10).unwrap_or(String::new());
        if hash.len() == 0 {
            return Redirect::to("/");
        }

        let new_user = User {
            username: user.username.clone(),
            password: hash,
        };
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(&*db_conn)
            .expect("Error inserting new user");
    }

    Redirect::to("/success")
}

#[get("/success")]
fn success() -> io::Result<NamedFile> {
    NamedFile::open("static/success.html")
}

#[get("/spectre.min.css")]
fn spectrecss() -> io::Result<NamedFile> {
    NamedFile::open("static/spectre.min.css")
}

fn main() {
    rocket::ignite()
        .attach(UsersDbConn::fairing())
        .mount("/", routes![index, login, success, spectrecss])
        .launch();
}
