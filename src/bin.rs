// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
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

pub mod cli;

use chrono::offset::Utc;
use chrono::DateTime;
use failure::{self, Fallible};
use std::path::PathBuf;
use std::process::exit;

use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp::Pgp;

fn real_main() -> Fallible<()> {
    use cli::*;
    use structopt::StructOpt;

    let cli = Cli::from_args();

    let mut ca = ca::Ca::new(cli.database.as_deref());

    match cli.cmd {
        Command::User { cmd } => match cmd {
            UserCommand::Add { email, name } => {
                // TODO: key-profile?

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.usercert_new(name.as_deref(), &email[..], true)?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.add_revocation(&revocation_file)?
            }

            UserCommand::Check { cmd } => match cmd {
                UserCheckSubcommand::Expiry { days } => {
                    // FIXME: set default in structopt?
                    check_expiry(&ca, days.unwrap_or(0))?;
                }
                UserCheckSubcommand::Sigs => {
                    check_sigs(&ca)?;
                }
            },
            UserCommand::Import {
                key_file,
                name,
                email,
                revocation_file,
            } => {
                let key = std::fs::read_to_string(key_file)?;
                let revoc = match revocation_file {
                    Some(filename) => Some(std::fs::read_to_string(filename)?),
                    None => None,
                };

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.usercert_import(
                    &key,
                    revoc.as_deref(),
                    name.as_deref(),
                    &email[..],
                )?;
            }
            UserCommand::Export { email } => {
                let certs = match email {
                    Some(email) => ca.get_usercerts(&email)?,
                    None => ca.get_all_usercerts()?,
                };
                certs.iter().for_each(|cert| println!("{}", cert.pub_cert));
            }
            UserCommand::List => list_users(&ca)?,
            UserCommand::ShowRevocations { email } => {
                show_revocations(&ca, &email)?
            }
            UserCommand::ApplyRevocation { id } => {
                let rev = ca.get_revocation_by_id(id)?;
                ca.apply_revocation(rev)?;
            }
        },
        Command::Ca { cmd } => match cmd {
            CaCommand::New { domain, name } => {
                ca.ca_new(&domain, name.as_deref())?;
            }
            CaCommand::Export => {
                let ca_key = ca.get_ca_pubkey_armored()?;
                println!("{}", ca_key);
            }
            CaCommand::ImportTsig { key_file } => {
                let key = std::fs::read_to_string(key_file)?;
                ca.import_tsig_for_ca(&key)?;
            }
            CaCommand::Show => ca.show_ca()?,
        },
        Command::Bridge { cmd } => match cmd {
            BridgeCommand::New {
                email,
                scope,
                remote_key_file,
            } => new_bridge(
                &ca,
                email.as_deref(),
                &remote_key_file,
                scope.as_deref(),
            )?,
            BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            BridgeCommand::List => list_bridges(&ca)?,
        },
        Command::Wkd { cmd } => match cmd {
            WkdCommand::Export { path } => {
                let (db_ca, _) = ca.get_ca()?.unwrap();
                ca.export_wkd(&db_ca.domainname, &path)?;
            }
        },
    }

    Ok(())
}

fn show_revocations(ca: &ca::Ca, email: &str) -> Fallible<()> {
    let usercerts = ca.get_usercerts(email)?;
    if usercerts.is_empty() {
        println!("No Users found");
    } else {
        for cert in usercerts {
            println!("Revocations for Usercert {:?}", cert.name);
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

fn check_sigs(ca: &ca::Ca) -> Fallible<()> {
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

fn check_expiry(ca: &ca::Ca, exp_days: u64) -> Fallible<()> {
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

fn list_users(ca: &ca::Ca) -> Fallible<()> {
    for (usercert, (sig_from_ca, tsig_on_ca)) in ca.usercert_signatures()? {
        println!(
            "usercert for '{}'",
            usercert
                .name
                .clone()
                .unwrap_or_else(|| "<no name>".to_string())
        );
        println!("fingerprint {}", usercert.fingerprint);

        ca.get_emails(&usercert)?
            .iter()
            .for_each(|email| println!("- email {}", email.addr));

        let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        if let Some(exp) = Pgp::get_expiry(&cert)? {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" cert doesn't expire");
        }

        println!(" user cert (or subkey) signed by CA: {}", sig_from_ca);
        println!(" user cert has tsigned CA: {}", tsig_on_ca);
        if Pgp::is_possibly_revoked(&cert) {
            println!(" this certificate has (possibly) been REVOKED");
        }
        println!();
    }

    Ok(())
}

fn list_bridges(ca: &ca::Ca) -> Fallible<()> {
    ca.get_bridges()?.iter().for_each(|bridge| {
        println!("Bridge '{}':\n\n{}", bridge.email, bridge.pub_key)
    });
    Ok(())
}

fn new_bridge(
    ca: &ca::Ca,
    email: Option<&str>,
    key_file: &PathBuf,
    scope: Option<&str>,
) -> Fallible<()> {
    let bridge = ca.bridge_new(key_file, email, scope)?;
    let remote = Pgp::armored_to_cert(&bridge.pub_key)?;

    println!("signed certificate for {} as bridge\n", bridge.email);
    println!("CAUTION:");
    println!("The fingerprint of the remote CA key is");
    println!("{}\n", remote.fingerprint());
    println!(
        "Please verify that this key is controlled by \
         {} before disseminating the signed remote certificate",
        bridge.email
    );
    Ok(())
}

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
