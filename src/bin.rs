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

use std::path::Path;
use std::process::exit;

use clap::crate_version;
use clap::load_yaml;
use clap::App;

use chrono::offset::Utc;
use chrono::DateTime;

use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp::Pgp;

use failure::{self, ResultExt};
pub type Result<T> = ::std::result::Result<T, failure::Error>;

fn real_main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let app = App::from_yaml(yaml).version(crate_version!());

    let matches = app.get_matches();

    let db = matches.value_of("database");

    let mut ca = ca::Ca::new(db);

    match matches.subcommand() {
        ("init", Some(_m)) => {
            unimplemented!("what should this do?");
        }
        ("wkd-export", Some(m)) => match m.value_of("path") {
            Some(path) => {
                let (db_ca, _) = ca.get_ca()?.unwrap();
                ca.export_wkd(&db_ca.domainname, Path::new(path))?;
            }
            _ => unimplemented!("missing domain name"),
        },
        ("ca", Some(m)) => match m.subcommand() {
            ("new", Some(m2)) => match m2.value_of("domain") {
                Some(domain) => {
                    ca.ca_new(&domain)?;
                }
                _ => unimplemented!("missing domain name"),
            },
            ("show", Some(_m2)) => {
                ca.show_ca()?;
            }
            ("export", Some(_m2)) => {
                let ca_key = ca.get_ca_pubkey_armored()?;
                println!("{}", ca_key);
            }
            ("import-tsig", Some(m2)) => {
                let key_file = m2.value_of("key-file").unwrap();
                let key = std::fs::read_to_string(key_file)?;
                ca.import_tsig_for_ca(&key)?;
            }

            _ => unimplemented!(),
        },
        ("user", Some(m)) => {
            match m.subcommand() {
                ("add", Some(m2)) => {
                    match m2.values_of("email") {
                        Some(email) => {
                            let email_vec = email.collect::<Vec<_>>();

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
                ("import", Some(m2)) => match m2.values_of("email") {
                    Some(email) => {
                        let email_vec = email.collect::<Vec<_>>();

                        let name = m2.value_of("name");

                        let key_file = m2.value_of("key-file").unwrap();
                        let revocation_file = m2.value_of("revocation-file");

                        let key = std::fs::read_to_string(key_file)?;

                        let revoc = match revocation_file {
                            Some(filename) => {
                                Some(std::fs::read_to_string(filename)?)
                            }
                            None => None,
                        };

                        ca.usercert_import(
                            &key,
                            revoc.as_deref(),
                            name,
                            &email_vec[..],
                        )?;
                    }
                    _ => unimplemented!(),
                },
                ("add-revocation", Some(m2)) => {
                    let revocation_file =
                        m2.value_of("revocation-file").unwrap();

                    ca.add_revocation(revocation_file)?;
                }
                ("apply-revocation", Some(m2)) => {
                    let id = m2.value_of("id").unwrap();
                    let id: i32 =
                        id.parse::<i32>().context("ID bad syntax")?;

                    let rev = ca.get_revocation_by_id(id)?;

                    ca.apply_revocation(rev)?;
                }
                ("export", Some(m2)) => {
                    match m2.value_of("email") {
                        Some(email) => {
                            for cert in ca.get_usercerts(email)? {
                                println!("{}", cert.pub_cert);
                            }
                        }
                        None => {
                            // bulk export
                            for cert in ca.get_all_usercerts()? {
                                println!("{}", cert.pub_cert);
                            }
                        }
                    }
                }
                ("show-revocations", Some(m2)) => {
                    if let Some(email) = m2.value_of("email") {
                        show_revocations(&ca, email)?;
                    }
                }
                ("check", Some(m)) => match m.subcommand() {
                    ("sigs", Some(_m2)) => {
                        check_sigs(&ca)?;
                    }
                    ("expiry", Some(m2)) => {
                        // check that keys are valid for at least this
                        // number of days from now
                        let exp_days = m2
                            .value_of("days")
                            .unwrap_or_else(|| "0")
                            .parse::<u64>()
                            .context("days parameter must be a number")?;
                        check_expiry(&ca, exp_days)?;
                    }
                    _ => unimplemented!(),
                },
                ("list", Some(_m2)) => {
                    list_users(&ca)?;
                }

                _ => unimplemented!("unexpected/missing subcommand"),
            }
        }
        ("bridge", Some(m)) => match m.subcommand() {
            ("new", Some(m2)) => {
                let scope = m2.value_of("scope");

                let key_file = m2.value_of("remote-key-file").unwrap();

                let email = m2.value_of("email");
                new_bridge(&ca, email, key_file, scope)?;
            }
            ("revoke", Some(m2)) => {
                let email = m2.value_of("email").unwrap();

                ca.bridge_revoke(email)?;
            }
            ("list", Some(_m2)) => {
                list_bridges(&ca)?;
            }

            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    }

    Ok(())
}

fn show_revocations(ca: &ca::Ca, email: &str) -> Result<()> {
    let usercerts = ca.get_usercerts(email)?;
    if usercerts.is_empty() {
        println!("User not found");
    } else {
        for cert in usercerts {
            println!("revocations for {:?}", cert.name);
            let revoc = ca.get_revocations(&cert)?;
            for r in revoc {
                println!(" revocation id {:?}", r.id);
                if r.published {
                    println!(" this revocation has been PUBLISHED");
                }
                println!("{}", r.revocation);
                println!();
            }
        }
    }
    Ok(())
}

fn check_sigs(ca: &ca::Ca) -> Result<()> {
    let mut count_ok = 0;

    let sigs_status = ca.usercert_signatures()?;
    for (usercert, (sig_from_ca, tsig_on_ca)) in &sigs_status {
        let ok = if *sig_from_ca {
            true
        } else {
            println!(
                "missing signature by CA for \
                 user {:?} fingerprint {}",
                usercert.name, usercert.fingerprint
            );
            false
        } && if *tsig_on_ca {
            true
        } else {
            println!(
                "CA Cert has not been tsigned \
                 by user {:?}",
                usercert.name
            );
            false
        };

        if ok {
            count_ok += 1;
        }
    }
    println!(
        "checked {} certs, {} of them had good signatures in both directions",
        sigs_status.len(),
        count_ok
    );

    Ok(())
}

fn check_expiry(ca: &ca::Ca, exp_days: u64) -> Result<()> {
    let expiries = ca.usercert_expiry(exp_days)?;

    for (usercert, (alive, expiry)) in expiries {
        println!(
            "name {}, fingerprint {}",
            usercert
                .name
                .clone()
                .unwrap_or_else(|| "<no name>".to_string()),
            usercert.fingerprint
        );

        if let Some(exp) = expiry {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" cert doesn't expire");
        }

        if !alive {
            println!(" user cert EXPIRED/EXPIRING: {:?}", usercert.name);
        }

        println!();
    }

    Ok(())
}

fn list_users(ca: &ca::Ca) -> Result<()> {
    for (usercert, (sig_from_ca, tsig_on_ca)) in ca.usercert_signatures()? {
        println!(
            "usercert for '{}'",
            usercert
                .name
                .clone()
                .unwrap_or_else(|| "<no name>".to_string())
        );

        println!("fingerprint {}", usercert.fingerprint);

        for email in ca.get_emails(&usercert)? {
            println!("- email {}", email.addr);
        }

        let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        if let Some(exp) = Pgp::get_expiry(&cert)? {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" cert doesn't expire");
        }

        println!(" user cert (or subkey) signed by CA: {}", sig_from_ca);
        println!(" user cert has tsigned CA: {}", tsig_on_ca);
        println!();
    }

    Ok(())
}

fn list_bridges(ca: &ca::Ca) -> Result<()> {
    for bridge in ca.get_bridges()? {
        println!("Bridge '{}':\n\n{}", bridge.email, bridge.pub_key);
    }
    Ok(())
}

fn new_bridge(
    ca: &ca::Ca,
    email: Option<&str>,
    key_file: &str,
    scope: Option<&str>,
) -> Result<()> {
    let bridge = ca.bridge_new(key_file, email, scope)?;
    let remote = Pgp::armored_to_cert(&bridge.pub_key)?;

    println!("signed certificate for {} as bridge\n", bridge.email);
    println!("CAUTION:");
    println!("The fingerprint of the remote CA key is");
    println!("{}\n", remote.fingerprint().to_string());
    println!(
        "Please verify that this key is controlled by \
         {} before disseminating the signed remote certificate",
        bridge.email
    );
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
