// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

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

                ca.user_new(name.as_deref(), &email[..], None, true)?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add_from_file(&revocation_file)?
            }

            UserCommand::Check { cmd } => match cmd {
                UserCheckSubcommand::Expiry { days } => {
                    print_expiry_status(&ca, days)?;
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
                    None,
                )?;
            }
            UserCommand::Export { email, path } => {
                ca.export_certs_as_files(email, path)?;
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
            CaCommand::Revocations { output } => {
                ca.ca_generate_revocations(output)?;
                println!("Wrote a set of revocations to the output file");
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
            } => ca.add_bridge(
                email.as_deref(),
                &remote_key_file,
                scope.as_deref(),
                commit,
            )?,
            BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            BridgeCommand::List => ca.list_bridges()?,
            BridgeCommand::Export { email } => ca.print_bridges(email)?,
        },
        Command::Wkd { cmd } => match cmd {
            WkdCommand::Export { path } => {
                let (db_ca, _) = ca.ca_get()?.unwrap();
                ca.wkd_export(&db_ca.domainname, &path)?;
            }
        },

        Command::Keylist { cmd } => match cmd {
            KeyListCommand::Export {
                path,
                signature_uri,
                force,
            } => {
                ca.export_keylist(path, signature_uri, force)?;
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

    let users = ca.users_get_all()?;
    for user in &users {
        for cert in ca.get_certs_by_user(&user)? {
            let (sig_from_ca, tsig_on_ca) =
                ca.cert_check_certifications(&cert)?;

            let ok = if !sig_from_ca.is_empty() {
                true
            } else {
                println!(
                    "No CA certification on any User ID of {}.",
                    cert.fingerprint
                );
                false
            } && if tsig_on_ca {
                true
            } else {
                println!(
                    "CA Cert has not been tsigned by {}.",
                    cert.fingerprint
                );
                false
            };

            if ok {
                count_ok += 1;
            }
        }
    }

    println!();
    println!(
        "Checked {} user keys, {} of them had good certifications in both \
        directions.",
        users.len(),
        count_ok
    );

    Ok(())
}

fn print_expiry_status(ca: &OpenpgpCa, exp_days: u64) -> Result<()> {
    let expiries = ca.certs_expired(exp_days)?;

    if expiries.is_empty() {
        println!("No certificates will expire in the next {} days.", exp_days);
    } else {
        println!(
            "The following {} certificates will expire in the next {} days.",
            expiries.len(),
            exp_days
        );
        println!();
    }

    for (cert, expiry) in expiries {
        let name = ca.cert_get_name(&cert)?;
        println!("name {}, fingerprint {}", name, cert.fingerprint);

        if let Some(exp) = expiry {
            let datetime: DateTime<Utc> = exp.into();
            println!(" expires: {}", datetime.format("%d/%m/%Y"));
        } else {
            println!(" no expiration date is set for this user key");
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

            println!("OpenPGP key {}", cert.fingerprint);
            println!(" for user '{}'", name);

            println!(" user cert signed by CA: {}", !sig_by_ca.is_empty());
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
