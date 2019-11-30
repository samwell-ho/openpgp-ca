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

use failure;

use openpgp_ca_lib::ca;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

fn real_main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

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
                        _ => unimplemented!(),
                    }
                }
                ("show", Some(_m2)) => {
                    ca.show_cas();
                }
                ("export", Some(_m2)) => {
                    ca.export_pubkey();
                }
                ("import-tsig", Some(m2)) => {
                    let key_file = m2.value_of("key-file").unwrap();
                    ca.import_tsig(key_file);
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
                ("list", Some(_m2)) => {
                    ca.list_users()?;
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
        eprint!("{}", cause);
        while let Some(c) = cause.cause() {
            eprint!(":\n  {}", c);
            cause = c;
        }
        eprintln!();
        exit(2);
    }
}