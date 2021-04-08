#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_contrib;

use rocket_contrib::templates::Template;

extern crate bcrypt;
extern crate rocket_client_addr;

use rocket::request::{Form, Request};
use rocket::response::{NamedFile, Redirect};
use rocket_client_addr::ClientAddr;
use std::{io, vec};

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

#[derive(serde::Serialize)]
struct Record {
    ip: String,
    usage: usize,
}

#[derive(serde::Serialize)]
struct TemplateContext {
    records: Vec<Record>,
}

#[database("user_db")]
struct UsersDbConn(diesel::SqliteConnection);

#[get("/")]
fn index(client_addr: ClientAddr) -> io::Result<NamedFile> {
    let addr = client_addr.get_ipv4().unwrap();
    eprintln!("{} is asking for WiFi.", addr);
    NamedFile::open("static/index.html")
}

#[get("/monitor")]
fn monitor() -> Template {
    let mut context = TemplateContext { records: vec![] };
    context.records.push(Record {
        ip: String::from("1.2.3.4"),
        usage: 7122 as usize,
    });
    Template::render("monitor", &context)
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

    let ipt = iptables::new(false).unwrap();
    let ifname = env!("IFNAME");
    assert!(ipt
        .insert(
            "nat",
            "PREROUTING",
            format!("-i {} -s {} -j ACCEPT", ifname, addr).as_str(),
            3 // TODO: Proper ordering
        )
        .is_ok());
    assert!(ipt
        .append(
            "filter",
            "FORWARD",
            format!("-i {} -s {} -j ACCEPT", ifname, addr).as_str()
        )
        .is_ok());

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

#[catch(404)]
fn not_found(_req: &Request) -> Redirect {
    Redirect::to("/")
}
fn main() {
    rocket::ignite()
        .register(catchers![not_found])
        .attach(UsersDbConn::fairing())
        .attach(Template::fairing())
        .mount("/", routes![index, login, monitor, success, spectrecss])
        .launch();
}
