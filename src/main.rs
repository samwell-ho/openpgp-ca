// Copyright 2019 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA.
//
// OpenPGP CA is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPGP CA is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPGP CA.  If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate clap;
extern crate failure;
extern crate sequoia_openpgp as openpgp;

use std::process::exit;

use clap::App;
use failure::ResultExt;

use db::Db;
use pgp::Pgp;

pub mod models;
pub mod schema;
pub mod db;
pub mod pgp;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

/// Usage example:
///
/// initialize db ("diesel migration run"), then:
///
/// cargo run ca new example_ca openpgp_ca@example.org
/// cargo run user add example_ca -e alice@example.org -e a@example.org -n Alicia
/// cargo run user add example_ca -e bob@example.org
fn real_main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    match matches.subcommand() {
        ("init", Some(_m)) => {
            init();
        }
        ("ca", Some(m)) => {
            match m.subcommand() {
                ("new", Some(m2)) => {
                    match (m2.value_of("name"), m2.values_of("email")) {
                        (Some(name), Some(email)) => {
                            let emails = email.into_iter().collect::<Vec<_>>();
                            ca_new(name, &emails)?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("delete", Some(m2)) => {
                    match m2.value_of("name") {
                        Some(name) => ca_delete(name)?,
                        _ => unimplemented!(),
                    }
                }
                ("list", Some(_m2)) => {
                    list_cas();
                }

                _ => unimplemented!(),
            }
        }
        ("user", Some(m)) => {
            println!("user");
            println!("{:?}", m);
            match m.subcommand() {
                ("add", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.into_iter()
                                .collect::<Vec<_>>();

                            let name = m2.value_of("name");

                            // TODO
                            // .arg(Arg::with_name("key-profile")
                            //  .long("key-profile")
                            //  .value_name("key-profile")
                            //  .help("Key Profile"))

                            let ca_name = m2.value_of("ca_name").unwrap();

                            user_new(name, Some(email_vec.as_ref()), ca_name)?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("list", Some(_m2)) => {
                    list_users()?;
                }

                _ => unimplemented!(),
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}


fn init() {
    println!("Initializing!");

    // FIXME what should this do?
    unimplemented!();
}


// -------- CAs

fn ca_new(name: &str, emails: &[&str]) -> Result<()> {
    println!("make ca '{}'", name);

    if emails.len() != 1 {
        unimplemented!("creating a CA should be done with exactly one email address");
    }

    let res = Pgp::make_private_ca_key(emails);
    if let Ok((tpk, revoc)) = res {
        let ca_uid = emails[0];
        let new_ca = models::NewCa {
            name,
            email: ca_uid.to_owned(),
            ca_key: &Pgp::priv_tpk_to_armored(&tpk)?,
            revoc_cert: &Pgp::sig_to_armored(&revoc)?,
        };

        Db::new().insert_ca(new_ca)?;

        println!("new CA: {}\n{:#?}", name, tpk);
    } else {
        unimplemented!("ca_new failed?!");
    }

    Ok(())
}

fn ca_delete(name: &str) -> Result<()> {

    // FIXME: CA should't be deleted while users point to it.
    // -> limit with database constraints? (or by rust code?)

    println!("delete ca '{}'", name);

    Db::new().delete_ca(name)?;

    Ok(())
}


fn get_ca_by_name(name: &str) -> Result<openpgp::TPK> {
    let ca = Db::new().search_ca(name)?;

    if let Some(ca) = ca {
        let ca_tpk = Pgp::armored_to_tpk(&ca.ca_key);

        println!("CA: {:#?}", ca_tpk);

        Ok(ca_tpk)
    } else {
        unimplemented!("get_domain_ca() failed");
    }
}

pub fn list_cas() {
    let db = Db::new();
    let cas = db.list_cas();
    for ca in cas {
        println!("{:#?}", ca);
    }
}


// -------- users

fn user_new(name: Option<&str>, emails: Option<&[&str]>, ca_name: &str)
            -> Result<()> {
    let ca_key = get_ca_by_name(ca_name).unwrap();

    println!("new user: uids {:?}, ca_name {}", emails, ca_name);

    // make user key (signed by CA)
    let (user, revoc) = Pgp::make_user(emails)
        .context("make_user_key failed")?;

    // sign user key with CA key
    let certified = Pgp::sign_user(&ca_key, &user).
        context("sign_user_key failed")?;

    println!("=== user_tpk certified {:#?}\n", certified);

    // user trusts CA key
    let trusted_ca = Pgp::trust_ca(&ca_key, &user).
        context("failed: user trusts CA")?;

    let trusted_ca_armored = Pgp::priv_tpk_to_armored(&trusted_ca)?;
    println!("updated armored CA key: {}", trusted_ca_armored);

    // now write new data to DB
    let db = Db::new();

    match db.search_ca(ca_name).context("Error searching CA")? {
        Some(mut ca) => {

            // store updated CA TPK in DB
            ca.ca_key = trusted_ca_armored;

            db.update_ca(&ca)?;

            // FIXME: the private key needs to be handed over to
            // the user -> print for now?
            let priv_key = &Pgp::priv_tpk_to_armored(&certified)?;
            println!("secret user key:\n{}", priv_key);
            // --

            let pub_key = &Pgp::tpk_to_armored(&certified)?;
            let revoc_cert = &Pgp::sig_to_armored(&revoc)?;

            let new_user = models::NewUser { name, pub_key, revoc_cert, cas_id: ca.id };

            let user_id = db.insert_user(new_user)?;
            for email in emails.unwrap() {
                let new_email = models::NewEmail { addr: email, user_id };
                db.insert_email(new_email)?;
            }

            Ok(())
        }
        _ => Err(failure::err_msg("CA not found"))
    }
}

pub fn list_users() -> Result<()> {
//    https://docs.diesel.rs/diesel/associations/index.html
    let db = Db::new();
    let users = db.list_users()?;
    for user in users {
        println!("#{} - Name: {:?}", user.id, user.name);

        let emails = db.get_emails(user)?;
        println!("  -> emails {:?}", emails);
    }

    Ok(())
}


// -------- bridges

// TODO: add bridge, ...
// for bridge: TSIG:  set_regular_expression + set_trust_signature + expiration

// -----------------


fn main() {
    if let Err(e) = real_main() {
        let mut cause = e.as_fail();
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}