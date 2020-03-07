// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
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

use openpgp_ca_lib::ca::OpenpgpCa;

fn real_main() -> Fallible<()> {
    use cli::*;
    use structopt::StructOpt;

    let cli = Cli::from_args();

    let ca = OpenpgpCa::new(cli.database.as_deref());

    match cli.cmd {
        Command::User { cmd } => match cmd {
            UserCommand::Add { email, name } => {
                // TODO: key-profile?

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.usercert_new(name.as_deref(), &email[..], true)?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add(&revocation_file)?
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
                let revoc_certs = match revocation_file {
                    Some(filename) => Some(std::fs::read_to_string(filename)?),
                    None => None,
                };

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.usercert_import_new(
                    &key,
                    revoc_certs.as_deref(),
                    name.as_deref(),
                    &email[..],
                )?;
            }
            UserCommand::Export { email } => {
                let certs = match email {
                    Some(email) => ca.usercerts_get(&email)?,
                    None => ca.usercerts_get_all()?,
                };
                certs.iter().for_each(|cert| println!("{}", cert.pub_cert));
            }
            UserCommand::List => list_users(&ca)?,
            UserCommand::ShowRevocations { email } => {
                show_revocations(&ca, &email)?
            }
            UserCommand::ApplyRevocation { id } => {
                let rev = ca.revocation_get_by_id(id)?;
                ca.revocation_apply(rev)?;
            }
        },
        Command::Ca { cmd } => match cmd {
            CaCommand::Init { domain, name } => {
                ca.ca_init(&domain, name.as_deref())?;
            }
            CaCommand::Export => {
                let ca_key = ca.ca_get_pubkey_armored()?;
                println!("{}", ca_key);
            }
            CaCommand::ImportTsig { key_file } => {
                let key = std::fs::read_to_string(key_file)?;
                ca.ca_import_tsig(&key)?;
            }
            CaCommand::Show => ca.ca_show()?,
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
                let (db_ca, _) = ca.ca_get()?.unwrap();
                ca.wkd_export(&db_ca.domainname, &path)?;
            }
        },
    }

    Ok(())
}

fn show_revocations(ca: &OpenpgpCa, email: &str) -> Fallible<()> {
    let usercerts = ca.usercerts_get(email)?;
    if usercerts.is_empty() {
        println!("No Users found");
    } else {
        for cert in usercerts {
            println!("Revocations for Usercert {:?}", cert.name);
            let revoc = ca.revocations_get(&cert)?;
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

fn check_sigs(ca: &OpenpgpCa) -> Fallible<()> {
    let mut count_ok = 0;

    let sigs_status = ca.usercerts_check_signatures()?;
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

fn check_expiry(ca: &OpenpgpCa, exp_days: u64) -> Fallible<()> {
    let expiries = ca.usercerts_expired(exp_days)?;

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

fn list_users(ca: &OpenpgpCa) -> Fallible<()> {
    for (usercert, (sig_by_ca, tsig_on_ca)) in
        ca.usercerts_check_signatures()?
    {
        println!(
            "usercert for '{}'",
            usercert
                .name
                .clone()
                .unwrap_or_else(|| "<no name>".to_string())
        );
        println!("fingerprint {}", usercert.fingerprint);

        ca.emails_get(&usercert)?
            .iter()
            .for_each(|email| println!("- email {}", email.addr));

        if let Some(exp) = OpenpgpCa::usercert_expiration(&usercert)? {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" cert doesn't expire");
        }

        println!(" user cert (or subkey) signed by CA: {}", sig_by_ca);
        println!(" user cert has tsigned CA: {}", tsig_on_ca);
        if OpenpgpCa::usercert_possibly_revoked(&usercert)? {
            println!(" this certificate has (possibly) been REVOKED");
        }
        println!();
    }

    Ok(())
}

fn list_bridges(ca: &OpenpgpCa) -> Fallible<()> {
    ca.bridges_get()?.iter().for_each(|bridge| {
        println!("Bridge '{}':\n\n{}", bridge.email, bridge.pub_key)
    });
    Ok(())
}

fn new_bridge(
    ca: &OpenpgpCa,
    email: Option<&str>,
    key_file: &PathBuf,
    scope: Option<&str>,
) -> Fallible<()> {
    let (bridge, fingerprint) = ca.bridge_new(key_file, email, scope)?;

    println!("signed certificate for {} as bridge\n", bridge.email);
    println!("CAUTION:");
    println!("The fingerprint of the remote CA key is");
    println!("{}\n", fingerprint);
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
