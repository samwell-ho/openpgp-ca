// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use anyhow::Result;
use chrono::offset::Utc;
use chrono::DateTime;

use openpgp_ca_lib::ca::OpenpgpCa;

pub mod cli;

fn main() -> Result<()> {
    use cli::*;
    use structopt::StructOpt;

    let cli = Cli::from_args();

    let ca = OpenpgpCa::new(cli.database.as_deref())?;

    match cli.cmd {
        Command::User { cmd } => match cmd {
            UserCommand::Add { email, name } => {
                // TODO: key-profile?

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.user_new(name.as_deref(), &email[..], true)?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add(&revocation_file)?
            }

            UserCommand::Check { cmd } => match cmd {
                UserCheckSubcommand::Expiry { days } => {
                    // FIXME: set default in structopt?
                    print_expiry_status(&ca, days.unwrap_or(0))?;
                }
                UserCheckSubcommand::Certifications => {
                    print_certifications_status(&ca)?;
                }
            },
            UserCommand::Import {
                key_file,
                name,
                email,
                revocation_file,
            } => {
                let key = std::fs::read_to_string(key_file)?;
                let mut revoc_certs: Vec<String> = Vec::new();
                for filename in revocation_file {
                    let rev = std::fs::read_to_string(filename)?;
                    revoc_certs.push(rev);
                }

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.cert_import_new(
                    &key,
                    revoc_certs,
                    name.as_deref(),
                    &email[..],
                )?;
            }
            UserCommand::Export { email } => {
                let certs = match email {
                    Some(email) => ca.certs_get(&email)?,
                    None => ca.user_certs_get_all()?,
                };
                certs.iter().for_each(|cert| println!("{}", cert.pub_cert));
            }
            UserCommand::List => print_users(&ca)?,
            UserCommand::ShowRevocations { email } => {
                print_revocations(&ca, &email)?
            }
            UserCommand::ApplyRevocation { hash } => {
                let rev = ca.revocation_get_by_hash(&hash)?;
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
                commit,
            } => new_bridge(
                &ca,
                email.as_deref(),
                &remote_key_file,
                scope.as_deref(),
                commit,
            )?,
            BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            BridgeCommand::List => print_bridges(&ca)?,
            BridgeCommand::Export { email } => export_bridges(&ca, email)?,
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

fn print_revocations(ca: &OpenpgpCa, email: &str) -> Result<()> {
    let certs = ca.certs_get(email)?;
    if certs.is_empty() {
        println!("No OpenPGP keys found");
    } else {
        for cert in certs {
            let name = ca.cert_get_name(&cert)?;

            println!(
                "Revocations for OpenPGP key {}, user \"{}\"",
                cert.fingerprint, name
            );
            let revoc = ca.revocations_get(&cert)?;
            for r in revoc {
                let (reason, time) = ca.revocation_details(&r)?;
                let time = if let Some(time) = time {
                    let datetime: DateTime<Utc> = time.into();
                    format!("{}", datetime.format("%d/%m/%Y"))
                } else {
                    "".to_string()
                };
                println!(" - revocation id {}: {} ({})", r.hash, reason, time);
                if r.published {
                    println!("   this revocation has been APPLIED");
                }

                println!();
            }
        }
    }
    Ok(())
}

fn print_certifications_status(ca: &OpenpgpCa) -> Result<()> {
    let mut count_ok = 0;
    let mut count_all = 0;

    for user in ca.users_get_all()? {
        for cert in ca.get_certs_by_user(&user)? {
            let (sig_from_ca, tsig_on_ca) =
                ca.cert_check_certifications(&cert)?;

            count_all += 1;

            let name = ca.cert_get_name(&cert);
            let ok = if sig_from_ca {
                true
            } else {
                println!(
                    "Missing certification by CA for user {:?} fingerprint {}.",
                    user.name, cert.fingerprint
                );
                false
            } && if tsig_on_ca {
                true
            } else {
                println!("CA Cert has not been tsigned by user {:?}", name);
                false
            };

            if ok {
                count_ok += 1;
            }
        }
    }

    println!(
        "Checked {} user keys, {} of them had good certifications in both \
        directions.",
        count_all, count_ok
    );

    Ok(())
}

fn print_expiry_status(ca: &OpenpgpCa, exp_days: u64) -> Result<()> {
    let expiries = ca.certs_expired(exp_days)?;

    for (cert, (alive, expiry)) in expiries {
        // let name = cert.name.clone().unwrap_or_else(|| "<no name>"
        //     .to_string());
        let name = ca.cert_get_name(&cert)?;
        println!("name {}, fingerprint {}", name, cert.fingerprint);

        if let Some(exp) = expiry {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" no expiration date is set for this user key");
        }

        if !alive {
            println!(" user key EXPIRED/EXPIRING!");
        }

        println!();
    }

    Ok(())
}

fn print_users(ca: &OpenpgpCa) -> Result<()> {
    for user in ca.users_get_all()? {
        let name = user.name.clone().unwrap_or_else(|| "<no name>".to_owned());

        for cert in ca.get_certs_by_user(&user)? {
            let (sig_by_ca, tsig_on_ca) =
                ca.cert_check_certifications(&cert)?;

            println!("OpenPGP key for '{}'", name);
            println!(" fingerprint {}", cert.fingerprint);

            println!(" user cert (or subkey) signed by CA: {}", sig_by_ca);
            println!(" user cert has tsigned CA: {}", tsig_on_ca);

            ca.emails_get(&cert)?
                .iter()
                .for_each(|email| println!(" - email {}", email.addr));

            if let Some(exp) = OpenpgpCa::cert_expiration(&cert)? {
                let datetime: DateTime<Utc> = exp.into();
                println!(" expires: {}", datetime.format("%d/%m/%Y"));
            } else {
                println!(" no expiration date is set for this user key");
            }

            let revs = ca.revocations_get(&cert)?;
            println!(" {} revocation certificate(s) available", revs.len());

            if OpenpgpCa::cert_possibly_revoked(&cert)? {
                println!(" this user key has (possibly) been REVOKED");
            }
            println!();
        }
    }

    Ok(())
}

fn print_bridges(ca: &OpenpgpCa) -> Result<()> {
    ca.bridges_get()?.iter().for_each(|bridge| {
        println!("Bridge to '{}', (scope: '{}'", bridge.email, bridge.scope)
    });
    Ok(())
}

fn export_bridges(ca: &OpenpgpCa, email: Option<String>) -> Result<()> {
    let bridges = if let Some(email) = email {
        vec![ca.bridges_search(&email)?]
    } else {
        ca.bridges_get()?
    };

    for bridge in bridges {
        let cert = ca.cert_by_id(bridge.cert_id)?;
        println!("{}", cert.unwrap().pub_cert);
    }

    Ok(())
}

fn new_bridge(
    ca: &OpenpgpCa,
    email: Option<&str>,
    key_file: &PathBuf,
    scope: Option<&str>,
    commit: bool,
) -> Result<()> {
    if commit {
        let (bridge, fingerprint) = ca.bridge_new(key_file, email, scope)?;

        println!("Signed OpenPGP key for {} as bridge.\n", bridge.email);
        println!("The fingerprint of the remote CA key is");
        println!("{}\n", fingerprint);
    } else {
        println!("Bridge creation DRY RUN.");
        println!();

        println!(
            "Please verify that this is the correct fingerprint for the \
            remote CA admin before continuing:"
        );
        println!();

        let key = std::fs::read_to_string(key_file)?;
        OpenpgpCa::print_cert_info(&key)?;

        println!();
        println!(
            "When you've confirmed that the remote key is correct, repeat \
            this command with the additional parameter '--commit' \
            to commit the OpenPGP CA bridge to the database."
        );
    }
    Ok(())
}
