#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

extern crate rocket_client_addr;

use rocket::request::Form;
use rocket::response::{NamedFile, Redirect};
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

#[get("/register")]
fn register() -> io::Result<NamedFile> {
    NamedFile::open("static/register.html")
}

#[post("/login?<is_register>", data = "<user>")]
fn login(
    user: Option<Form<LoginInfo>>,
    is_register: Option<bool>,
    client_addr: ClientAddr,
) -> Redirect {
    let is_register = is_register.unwrap_or_default();
    let addr = client_addr.get_ipv4().unwrap();
    eprintln!("is_register = {} addr = {}", is_register, addr);
    match user {
        None => eprintln!("none"),
        Some(info) => eprintln!("name: {}, password: {}", info.username, info.password),
    }
    Redirect::to("/success")
}

#[get("/success")]
fn success() -> io::Result<NamedFile> {
    NamedFile::open("static/success.html")
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, login, register, success])
        .launch();
}
