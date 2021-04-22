#![feature(proc_macro_hygiene, decl_macro)]
#![feature(slice_group_by)]

#[macro_use]
extern crate rocket;

#[macro_use]
extern crate rocket_contrib;

use rocket_contrib::templates::Template;

extern crate bcrypt;
extern crate rocket_client_addr;

use rocket::request::{Form, Request};
use rocket::response::status::Forbidden;
use rocket::response::{NamedFile, Redirect};
use rocket_client_addr::ClientAddr;
use std::net::Ipv4Addr;
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
struct User {
    username: String,
    password: String,
}

#[derive(serde::Serialize, PartialEq, fmt::Debug)]
struct Record {
    ip: String,
    packets: usize,
    bandwidth: usize,
    blocked: bool,
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
    let mut records: Vec<_> = output
        .lines()
        .skip(2)
        .into_iter()
        .map(|line| {
            let stat: Vec<_> = line.split_whitespace().into_iter().collect();
            let index = if stat[7] == "0.0.0.0/0" { 8 } else { 7 };
            Record {
                ip: String::from(stat[index]),
                packets: stat[0].parse::<usize>().unwrap(),
                bandwidth: stat[1].parse::<usize>().unwrap(),
                blocked: stat[2] == "DROP",
            }
        })
        .collect();
    records.sort_by(|a, b| a.ip.cmp(&b.ip));
    records
        .group_by(|a, b| a.ip == b.ip)
        .map(|x| {
            let mut bandwidth_sum: usize = 0;
            let mut packet_sum: usize = 0;
            let mut blocked_sum: bool = false;
            for y in x {
                bandwidth_sum += y.bandwidth;
                packet_sum += y.packets;
                blocked_sum |= y.blocked;
            }
            Record {
                ip: x[0].ip.clone(),
                blocked: blocked_sum,
                bandwidth: bandwidth_sum,
                packets: packet_sum,
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
            packets: 424 as usize,
            bandwidth: 69044 as usize,
            blocked: false,
        }]
    );
    let output = String::from(
        r#"Chain FORWARD (policy ACCEPT 57482 packets, 55M bytes)
 pkts bytes target     prot opt in     out     source               destination
  424 69044 DROP       all  --  ap0    *       192.168.12.34        0.0.0.0/0   "#,
    );
    assert_eq!(
        parse_iptables(output),
        vec![Record {
            ip: String::from("192.168.12.34"),
            packets: 424 as usize,
            bandwidth: 69044 as usize,
            blocked: true,
        }]
    );
}

#[get("/monitor")]
fn monitor(client_addr: ClientAddr) -> Result<Template, Forbidden<&'static str>> {
    let src_addr = client_addr.get_ipv4().unwrap();
    if src_addr != Ipv4Addr::new(127, 0, 0, 1) {
        return Err(Forbidden(Some("Source not from localhost.")));
    }
    let output = Command::new("sh")
        .arg("-c")
        .arg("iptables -vnxL FORWARD -t filter")
        .output()
        .expect("Failed to execute iptables -vnxL");
    let context = TemplateContext {
        records: parse_iptables(String::from_utf8(output.stdout).unwrap()),
    };
    Ok(Template::render("monitor", &context))
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
    let ifname = std::env::var("IFNAME").unwrap();
    assert!(ipt
        .insert(
            "nat",
            "PREROUTING",
            format!("-i {} -s {} -j ACCEPT", ifname, addr).as_str(),
            3
        )
        .is_ok());
    assert!(ipt
        .append(
            "filter",
            "FORWARD",
            format!(
                "-i {} -s {} -m conntrack --ctstate NEW -j ACCEPT",
                ifname, addr
            )
            .as_str()
        )
        .is_ok());
    assert!(ipt
        .append(
            "filter",
            "FORWARD",
            format!(
                "-s {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                addr
            )
            .as_str()
        )
        .is_ok());
    assert!(ipt
        .append(
            "filter",
            "FORWARD",
            format!(
                "-d {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                addr
            )
            .as_str()
        )
        .is_ok());

    Redirect::to("/success")
}

#[post("/block/<ip>")]
fn block(
    ip: Option<String>,
    client_addr: ClientAddr,
) -> Result<NamedFile, Forbidden<&'static str>> {
    let src_addr = client_addr.get_ipv4().unwrap();
    if src_addr != Ipv4Addr::new(127, 0, 0, 1) {
        return Err(Forbidden(Some("Source not from localhost.")));
    }
    let addr = ip.unwrap();
    eprintln!("Blocking {}", addr);
    let ipt = iptables::new(false).unwrap();
    let ifname = std::env::var("IFNAME").unwrap();
    assert!(ipt
        .delete(
            "nat",
            "PREROUTING",
            format!("-i {} -s {} -j ACCEPT", ifname, addr).as_str()
        )
        .is_ok());
    assert!(ipt
        .delete(
            "filter",
            "FORWARD",
            format!(
                "-i {} -s {} -m conntrack --ctstate NEW -j ACCEPT",
                ifname, addr
            )
            .as_str()
        )
        .is_ok());
    assert!(ipt
        .delete(
            "filter",
            "FORWARD",
            format!(
                "-s {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                addr
            )
            .as_str()
        )
        .is_ok());
    assert!(ipt
        .delete(
            "filter",
            "FORWARD",
            format!(
                "-d {} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                addr
            )
            .as_str()
        )
        .is_ok());
    assert!(ipt
        .insert(
            "filter",
            "FORWARD",
            format!("-i {} -s {} -j DROP", ifname, addr).as_str(),
            1
        )
        .is_ok());
    assert!(ipt
        .insert(
            "filter",
            "INPUT",
            format!("-i {} -s {} -j DROP", ifname, addr).as_str(),
            1
        )
        .is_ok());
    Ok(NamedFile::open("static/success.html").unwrap())
}

#[post("/unblock/<ip>")]
fn unblock(ip: Option<String>) -> io::Result<NamedFile> {
    let addr = ip.unwrap();
    eprintln!("Unblocking {}", addr);
    let ipt = iptables::new(false).unwrap();
    let ifname = std::env::var("IFNAME").unwrap();
    assert!(ipt
        .delete(
            "filter",
            "FORWARD",
            format!("-i {} -s {} -j DROP", ifname, addr).as_str()
        )
        .is_ok());
    assert!(ipt
        .delete(
            "filter",
            "INPUT",
            format!("-i {} -s {} -j DROP", ifname, addr).as_str()
        )
        .is_ok());
    NamedFile::open("static/success.html")
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
fn not_found(_: &Request) -> Redirect {
    Redirect::to("/")
}

fn main() {
    rocket::ignite()
        .register(catchers![not_found])
        .attach(UsersDbConn::fairing())
        .attach(Template::fairing())
        .mount(
            "/",
            routes![index, login, monitor, block, unblock, success, spectrecss],
        )
        .launch();
}
