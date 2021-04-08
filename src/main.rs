#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_contrib;

use rocket_contrib::templates::Template;

extern crate bcrypt;
extern crate rocket_client_addr;

use rocket::request::Form;
use rocket::response::{NamedFile, Redirect};
use rocket_client_addr::ClientAddr;
use std::process::Command;
use std::{fmt, io, vec};

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

#[derive(serde::Serialize, PartialEq, Eq, fmt::Debug)]
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

fn parse_iptables(output: String) -> Vec<Record> {
    output
        .lines()
        .skip(2)
        .into_iter()
        .map(|line| {
            let stat: Vec<_> = line.split_whitespace().into_iter().collect();
            Record {
                ip: String::from(stat[7]),
                usage: stat[0].parse::<usize>().unwrap(),
            }
        })
        .collect()
}

#[test]
fn test_parse_iptables() {
    let output = String::from(
        r#"Chain FORWARD (policy ACCEPT 57482 packets, 55M bytes)
 pkts bytes target     prot opt in     out     source               destination
  424 69044 ACCEPT     all  --  ap0    *       192.168.12.34        0.0.0.0/0   "#,
    );
    assert_eq!(
        parse_iptables(output),
        vec![Record {
            ip: String::from("192.168.12.34"),
            usage: 424 as usize,
        }]
    );
}

#[get("/monitor")]
fn monitor() -> Template {
    let output = Command::new("sh")
        .arg("-c")
        .arg("iptables -vnL FORWARD -t filter")
        .output()
        .expect("Failed to execute iptables -vnL");
    let context = TemplateContext {
        records: parse_iptables(String::from_utf8(output.stdout).unwrap()),
    };
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

fn main() {
    rocket::ignite()
        .attach(UsersDbConn::fairing())
        .attach(Template::fairing())
        .mount("/", routes![index, login, monitor, success, spectrecss])
        .launch();
}
