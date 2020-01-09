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
use std::path::Path;

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
        ("wkd-export", Some(m)) => {
            match m.value_of("path") {
                Some(path) => {
                    let (foo, _) = ca.get_ca()?.unwrap();
                    ca.export_wkd(&foo.domainname, Path::new(path))?;
                }
                _ => unimplemented!("missing domain name"),
            }
        }
        ("ca", Some(m)) => {
            match m.subcommand() {
                ("new", Some(m2)) => {
                    match m2.value_of("domain") {
                        Some(domain) => {
                            ca.ca_new(&domain)?;
                        }
                        _ => unimplemented!("missing domain name"),
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

                            ca.user_new(name, &email_vec[..])?;
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

                            ca.user_import(name, &email_vec[..],
                                           key_file, revocation_file,
                            )?;
                        }
                        _ => unimplemented!(),
                    }
                }
                ("add-revocation", Some(m2)) => {
                    let revocation_file =
                        m2.value_of("revocation-file").unwrap();

                    ca.add_revocation(revocation_file)?;
                }
                ("export", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.into_iter()
                                .collect::<Vec<_>>();

                            let users = ca.get_users(email_vec[0])?;
                            for u in users {
                                let certs = ca.get_user_certs(&u)?;
                                for cert in certs {
                                    println!("{}", cert.pub_cert);
                                }
                            }
                        }
                        None => {
                            // bulk export
                            for u in ca.get_all_users()? {
                                let certs = ca.get_user_certs(&u)?;
                                for cert in certs {
                                    println!("{}", cert.pub_cert);
                                }
                            }
                        }
                    }
                }
                ("revocation", Some(m2)) => {
                    if let Some(email) = m2.values_of("email") {
                        let email = email.into_iter().next().unwrap();

                        let users = ca.get_users(email)?;
                        if users.is_empty() {
                            println!("User not found");
                        } else {
                            for user in users {
                                let certs = ca.get_user_certs(&user)?;
                                for cert in certs {
                                    let revoc = ca.get_revocations(&cert)?;
                                    println!("{:?}", revoc);
                                }
                            }
                        }
                    }
                }
                ("check", Some(m)) => {
                    match m.subcommand() {
                        ("sigs", Some(_m2)) => {
                            for user in ca.get_all_users()
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

                            for user in ca.get_all_users()
                                .context("couldn't load users")? {
                                let certs = ca.get_user_certs(&user)?;
                                for cert in certs {
                                    let cert = Pgp::armored_to_cert(&cert.pub_cert);
                                    println!(" expires: {:?}", Pgp::get_expiry(&cert));
                                }
                            }
                        }
                        _ => unimplemented!(),
                    }
                }
                ("list", Some(_m2)) => {
                    let users = ca.get_all_users()?;

                    for user in users {
                        println!("{} (id {})",
                                 user.name.clone()
                                     .unwrap_or("<no name>".to_string()),
                                 user.id);

                        let certs = ca.get_user_certs(&user)?;
                        for usercert in certs {
                            println!(" cert {}, fingerprint {}",
                                     usercert.id, usercert.fingerprint);

                            let cert = Pgp::armored_to_cert(&usercert.pub_cert);

                            for email in ca.get_emails(&user)? {
                                println!("- email {}", email.addr);
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
                }

                _ => unimplemented!("unexpected/missing subcommand"),
            }
        }
        ("bridge", Some(m)) => {
            match m.subcommand() {
                ("new", Some(m2)) => {
                    let scope = m2.value_of("scope");

                    let key_file =
                        m2.value_of("remote-key-file").unwrap();

                    let name = m2.value_of("name");

                    let bridge = ca.bridge_new(key_file, name, scope)?;
                    let remote = Pgp::armored_to_cert(&bridge.pub_key);
                    println!("configured bridge '{}'\n", bridge.name);
                    println!("CAUTION: the fingerprint of the remote CA key \
                    is '{}'\n",
                             remote.fingerprint().to_string());
                    println!("Please make sure this fingerprint belongs to \
                    the remote party you want to bridge to before \
                    diseminating the bridging trust signature from\
                    OpenPGP CA");
                }
                ("revoke", Some(m2)) => {
                    let name = m2.value_of("name").unwrap();

                    ca.bridge_revoke(name)?;
                }
                ("list", Some(_m2)) => {
                    let bridges = ca.get_bridges()?;

                    for bridge in bridges {
                        println!("Bridge '{}':\n\n{}", bridge.name, bridge.pub_key);
                    }
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