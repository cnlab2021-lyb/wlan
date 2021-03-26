#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use rocket::request::Form;
use rocket::response::NamedFile;
use std::io;

#[get("/")]
fn index() -> io::Result<NamedFile> {
    NamedFile::open("static/index.html")
}

#[derive(FromForm)]
struct LoginInfo {
    username: String,
    password: String,
}

#[post("/login", data = "<user>")]
fn login(user: Option<Form<LoginInfo>>) -> &'static str {
    match user {
        None => eprintln!("none"),
        Some(info) => eprintln!("name: {}, password: {}", info.username, info.password),
    }
    "login"
}

fn main() {
    rocket::ignite().mount("/", routes![index, login]).launch();
}
