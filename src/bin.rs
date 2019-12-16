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

use std::process::exit;

use clap::App;
use clap::load_yaml;
use clap::crate_version;

use failure::{self, ResultExt};

use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp::Pgp;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

fn real_main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml).version(crate_version!());

    let matches = app.get_matches();

    let db = matches.value_of("database");

    let mut ca = ca::Ca::new(db);

    match matches.subcommand() {
        ("init", Some(_m)) => {
            ca.init();
        }
        ("ca", Some(m)) => {
            match m.subcommand() {
                ("new", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let emails = email.into_iter().collect::<Vec<_>>();
                            ca.ca_new(&emails)?;
                        }
                        _ => unimplemented!("missing email"),
                    }
                }
                ("show", Some(_m2)) => {
                    ca.show_cas()?;
                }
                ("export", Some(_m2)) => {
                    let ca_key = ca.export_pubkey()?;
                    println!("{}", ca_key);
                }
                ("import-tsig", Some(m2)) => {
                    let key_file = m2.value_of("key-file").unwrap();
                    ca.import_tsig(key_file)?;
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
                            // .arg(Arg::with_name("key-profile")
                            //  .long("key-profile")
                            //  .value_name("key-profile")
                            //  .help("Key Profile"))

                            ca.user_new(name, Some(email_vec.as_ref()))?;
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

                            let key_file = m2.value_of("key-file").unwrap();
                            let revocation_file = m2.value_of
                            ("revocation-file");

                            ca.user_import(name, Some(email_vec.as_ref()),
                                           key_file, revocation_file,
                            )?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("update-revocation", Some(m2)) => {
                    if let Some(email) = m2.values_of("email") {
                        let email = email.into_iter().next().unwrap();

                        let revocation_file =
                            m2.value_of("revocation-file").unwrap();

                        ca.update_revocation(email, revocation_file)?;
                    }
                }
                ("export", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.into_iter()
                                .collect::<Vec<_>>();

                            let u = ca.get_user(email_vec[0])?;
                            if let Some(u) = u {
                                println!("{}", u.pub_key);
                            }
                        }
                        None => {
                            // bulk export
                            ca.get_users()?.iter()
                                .for_each(|u| println!("{}", u.pub_key));
                        }
                    }
                }
                ("revocation", Some(m2)) => {
                    if let Some(email) = m2.values_of("email") {
                        let email = email.into_iter().next().unwrap();

                        if let Some(user) = ca.get_user(email)? {
                            if user.revoc_cert.is_some() {
                                println!("{}", user.revoc_cert.unwrap());
                            } else {
                                println!("no revocation cert available");
                            }
                        } else {
                            println!("User not found");
                        }
                    }
                }
                ("check", Some(m)) => {
                    match m.subcommand() {
                        ("sigs", Some(_m2)) => {
                            for user in ca.get_users()
                                .context("couldn't load users")? {
                                let ca_sig = ca.check_ca_sig(&user).
                                    context("Failed while checking CA sig")?;
                                if !ca_sig {
                                    println!("missing signature by CA for \
                                    user {:?}", user.name);
                                }

                                let tsig_on_ca = ca.check_ca_has_tsig(&user).
                                    context("Failed while checking tsig on CA")?;
                                if !tsig_on_ca {
                                    println!("CA Cert has not been tsigned \
                                    by user {:?}", user.name);
                                }
                            }
                        }
                        ("expiry", Some(_m2)) => {
                            // FIXME: use "days" argument

                            for user in ca.get_users()
                                .context("couldn't load users")? {
                                let cert = Pgp::armored_to_cert(&user.pub_key);
                                println!(" expires: {:?}", Pgp::get_expiry(&cert));
                            }
                        }
                        _ => unimplemented!(),
                    }
                }
                ("list", Some(_m2)) => {
                    let users = ca.get_users()?;

                    for user in users {
                        println!("{} (id {})",
                                 user.name.clone()
                                     .unwrap_or("<no name>".to_string()),
                                 user.id);

                        let cert = Pgp::armored_to_cert(&user.pub_key);

                        for email in ca.get_emails(&user)? {
                            println!("- {}", email.addr);
                        }

                        println!(" expires: {:?}", Pgp::get_expiry(&cert));

                        let ca_sig = ca.check_ca_sig(&user).
                            context("Failed while checking CA sig")?;
                        println!(" user key (or subkey) signed by CA: {}",
                                 ca_sig);

                        let tsig_on_ca = ca.check_ca_has_tsig(&user).
                            context("Failed while checking tsig on CA")?;
                        println!(" user has tsigned CA: {}", tsig_on_ca);

                        println!();
                    }
                }

                _ => unimplemented!("unexpected/missing subcommand"),
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
                                m2.value_of("remote-key-file").unwrap();

                            let name = m2.value_of("name").unwrap();

                            ca.bridge_new(name, key_file,
                                          Some(regex_vec.as_ref()))?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("revoke", Some(m2)) => {
                    let name = m2.value_of("name").unwrap();

                    ca.bridge_revoke(name)?;
                }
                ("list", Some(_m2)) => {
                    ca.list_bridges()?;
                }

                _ => unimplemented!(),
            }
        }
        _ => unimplemented!(),
    }

    Ok(())
}

// -----------------

fn main() {
    if let Err(e) = real_main() {
        let mut cause = e.as_fail();
        eprint!("ERROR: {}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}