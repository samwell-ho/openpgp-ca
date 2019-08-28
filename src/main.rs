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

use openpgp::parse::Parse;

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
///
/// cargo run user add example_ca -e alice@example.org -e a@example.org -n Alicia
/// cargo run user add example_ca -e bob@example.org
///
/// cargo run user import example_ca -e heiko@example.org -n Heiko --key_file ~/heiko.pubkey
///
/// cargo run bridge new -r "*@foo.de" --remote_key_file /tmp/bar.txt --name foobridge example_ca
/// cargo run bridge revoke --name foobridge
///
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
            match m.subcommand() {
                ("add", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.into_iter()
                                .collect::<Vec<_>>();

                            let name = m2.value_of("name");

                            // TODO
                            // .arg(Arg::with_name("key_profile")
                            //  .long("key_profile")
                            //  .value_name("key_profile")
                            //  .help("Key Profile"))

                            let ca_name = m2.value_of("ca_name").unwrap();


                            user_new(name, Some(email_vec.as_ref()), ca_name)?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("import", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.into_iter()
                                .collect::<Vec<_>>();

                            let name = m2.value_of("name");

                            let key_file = m2.value_of("key_file").unwrap();

                            let ca_name = m2.value_of("ca_name").unwrap();

                            // FIXME: optionally import revoc cert from file?
                            user_import(name, Some(email_vec.as_ref()),
                                        ca_name, key_file, None)?;
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
        ("bridge", Some(m)) => {
            match m.subcommand() {
                ("new", Some(m2)) => {
                    match m2.values_of("regex") {
                        Some(regex) => {
                            let regex_vec = regex.into_iter()
                                .collect::<Vec<_>>();

                            let key_file =
                                m2.value_of("remote_key_file").unwrap();

                            let name = m2.value_of("name").unwrap();

                            let ca_name = m2.value_of("ca_name").unwrap();

                            bridge_new(name, ca_name, key_file,
                                       Some(regex_vec.as_ref()))?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("revoke", Some(m2)) => {
                    let name = m2.value_of("name").unwrap();

                    bridge_revoke(name)?;
                }
                ("list", Some(_m2)) => {
                    list_bridges()?;
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
        context("sign_user failed")?;

    println!("=== user_tpk certified {:#?}\n", certified);

    // user trusts CA key
    let trusted_ca = Pgp::trust_ca(&ca_key, &user).
        context("failed: user trusts CA")?;

    let trusted_ca_armored = Pgp::priv_tpk_to_armored(&trusted_ca)?;
    println!("updated armored CA key: {}", trusted_ca_armored);

    // now write new data to DB
    let db = Db::new();

    let mut ca_db = db.search_ca(ca_name).context("Couldn't find CA")?.unwrap();

    // store updated CA TPK in DB
    ca_db.ca_key = trusted_ca_armored;

    db.update_ca(&ca_db)?;

    // FIXME: the private key needs to be handed over to
    // the user -> print for now?
    let priv_key = &Pgp::priv_tpk_to_armored(&certified)?;
    println!("secret user key:\n{}", priv_key);
    // --

    let pub_key = &Pgp::tpk_to_armored(&certified)?;
    let revoc = &Pgp::sig_to_armored(&revoc)?;

    let new_user = models::NewUser {
        name,
        pub_key,
        revoc_cert: Some(revoc),
        cas_id:
        ca_db.id,
    };

    let user_id = db.insert_user(new_user)?;
    for email in emails.unwrap() {
        let new_email = models::NewEmail { addr: email, user_id };
        db.insert_email(new_email)?;
    }

    Ok(())
}

fn user_import(name: Option<&str>, emails: Option<&[&str]>, ca_name: &str,
               key_file: &str, revoc_file: Option<&str>) -> Result<()> {
    let ca_key = get_ca_by_name(ca_name).unwrap();

    let user_key = openpgp::TPK::from_file(key_file)
        .expect("Failed to read key");

    if let Some(_filename) = revoc_file {
        // FIXME: handle optional revocation cert
    }

    // sign only the userids that have been specified
    let certified =
        match emails {
            Some(e) => Pgp::sign_user_emails(&ca_key, &user_key, e)?,
            None => user_key
        };

    // put in DB
    let db = Db::new();
    let ca_db = db.search_ca(ca_name).context("Couldn't find CA")?.unwrap();

    let pub_key = &Pgp::tpk_to_armored(&certified)?;
    let new_user =
        models::NewUser { name, pub_key, revoc_cert: None, cas_id: ca_db.id };

    let user_id = db.insert_user(new_user)?;
    for email in emails.unwrap() {
        let new_email = models::NewEmail { addr: email, user_id };
        db.insert_email(new_email)?;
    }

    Ok(())
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

fn bridge_new(name: &str, ca_name: &str, key_file: &str,
              regexes: Option<&[&str]>) -> Result<()> {
    let ca_key = get_ca_by_name(ca_name).unwrap();

    let remote_ca_key = openpgp::TPK::from_file(key_file)
        .expect("Failed to read key");

    // expect exactly one userid in remote CA key (otherwise fail)
    assert_eq!(remote_ca_key.userids().len(), 1, "remote CA should have \
    exactly one userid, but has {}", remote_ca_key.userids().len());

    let bridged = Pgp::bridge_to_remote_ca(&ca_key, &remote_ca_key, regexes)?;

    // store in DB
    let db = Db::new();
    let ca_db = db.search_ca(ca_name).context("Couldn't find CA")?.unwrap();

    let pub_key = &Pgp::tpk_to_armored(&bridged)?;

    let new_bridge = models::NewBridge {
        name,
        pub_key,
        cas_id:
        ca_db.id,
    };

    db.insert_bridge(new_bridge)?;

    Ok(())
}

pub fn bridge_revoke(name: &str) -> Result<()> {
    let db = Db::new();

    let bridge = db.search_bridge(name)?;
    assert!(bridge.is_some(), "bridge not found");

    let mut bridge = bridge.unwrap();

    println!("bridge {:?}", &bridge.clone());
    let ca_id = bridge.clone().cas_id;

    let ca = db.get_ca(ca_id)?.unwrap();
    let ca_key = Pgp::armored_to_tpk(&ca.ca_key);

    let bridge_pub = Pgp::armored_to_tpk(&bridge.pub_key);

    // make sig to revoke bridge
    let (rev_cert, rev_tpk) = Pgp::bridge_revoke(&bridge_pub, &ca_key)?;

    let revoc_cert_arm = &Pgp::sig_to_armored(&rev_cert)?;
    println!("revoc cert:\n{}", revoc_cert_arm);

    // save updated key (with revocation) to DB
    let revoked_arm = Pgp::tpk_to_armored(&rev_tpk)?;
    println!("revoked remote key:\n{}", &revoked_arm);

    bridge.pub_key = revoked_arm;
    db.update_bridge(&bridge)?;

    Ok(())
}


pub fn list_bridges() -> Result<()> {
    let bridges = Db::new().list_bridges()?;

    for bridge in bridges {
        println!("Bridge '{}':\n\n{}", bridge.name, bridge.pub_key);
    }

    Ok(())
}

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