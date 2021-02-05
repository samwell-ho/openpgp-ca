// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use chrono::offset::Utc;
use chrono::DateTime;

use openpgp_ca_lib::ca::OpenpgpCa;
use openpgp_keylist::{Key, Keylist, Metadata};

pub mod cli;

// export filename of keylist
const KEYLIST_FILE: &str = "keylist.json";

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
                    None,
                )?;
            }
            UserCommand::Export { email, path } => {
                export_certs(&ca, email, path)?;
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

        Command::Keylist { cmd } => match cmd {
            KeyListCommand::Export {
                path,
                signature_uri,
                force,
            } => {
                export_keylist(&ca, path, signature_uri, force)?;
            }
        },
    }

    Ok(())
}

fn export_certs(
    oca: &OpenpgpCa,
    email: Option<String>,
    path: Option<String>,
) -> Result<()> {
    if let Some(path) = path {
        // export to filesystem, individual files split by email

        let emails = if let Some(email) = email {
            vec![email]
        } else {
            oca.get_emails_all()?
                .iter()
                .map(|ce| ce.addr.clone())
                .collect()
        };

        for email in &emails {
            if let Ok(certs) = oca.certs_get(email) {
                if !certs.is_empty() {
                    let mut c: Vec<_> = vec![];
                    for cert in certs {
                        c.push(OpenpgpCa::armored_to_cert(&cert.pub_cert)?);
                    }

                    std::fs::write(
                        path_append(&path, email)?,
                        OpenpgpCa::certs_to_armored(&c)?,
                    )?;
                }
            } else {
                println!("ERROR loading certs for email '{}'", email)
            };
        }
    } else {
        // write to stdout
        let certs = match email {
            Some(email) => oca.certs_get(&email)?,
            None => oca.user_certs_get_all()?,
        };

        let mut c = Vec::new();
        for cert in certs {
            c.push(OpenpgpCa::cert_to_cert(&cert)?);
        }

        println!("{}", OpenpgpCa::certs_to_armored(&c)?);
    }

    Ok(())
}

// Append a (potentially adversarial) `filename` to a (presumed trustworthy)
// `path`.
//
// If `filename` contains suspicious chars, this fn returns an Err.
fn path_append(path: &str, filename: &str) -> Result<PathBuf> {
    // colon is a special char on windows (and illegal in emails)
    if filename.chars().any(std::path::is_separator)
        || filename.chars().any(|c| c == ':')
    {
        Err(anyhow::anyhow!(
            "filename contains special character - maybe a path traversal \
            attack? {}",
            filename
        ))
    } else {
        let mut pb = PathBuf::from_str(path)?;
        pb.push(filename);
        Ok(pb)
    }
}

/// Export the contents of a CA in Keylist format.
///
/// `path`: filesystem path into which the exported keylist and signature
/// files will be written.
///
/// `signature_uri`: the https address from which the signature file will
/// be retrievable
///
/// `force`: by default, this fn fails if the files exist; when force is
/// true, overwrite.
fn export_keylist(
    oca: &OpenpgpCa,
    path: PathBuf,
    signature_uri: String,
    force: bool,
) -> Result<()> {
    // filename of sigfile: last part of signature_uri
    let pos = &signature_uri.rfind('/').unwrap() + 1; //FIXME
    let sigfile_name = &signature_uri[pos..];

    // Start populating new Keylist
    let mut ukl = Keylist {
        metadata: Metadata {
            signature_uri: signature_uri.clone(),
            keyserver: None,
            comment: Some("Exported from OpenPGP CA".to_string()),
        },
        keys: vec![],
    };

    // .. add ca cert to Keylist ..
    let (ca, cacert) = oca.ca_get()?.expect("failed to load CA");

    ukl.keys.push(Key {
        fingerprint: cacert.fingerprint,
        name: Some(format!("OpenPGP CA at {}", ca.domainname)),
        email: Some(oca.get_ca_email()?),
        comment: None,
        keyserver: None,
    });

    // .. add all "signed-by-ca" certs to the list.
    for user in &oca.users_get_all()? {
        for user_cert in oca.get_certs_by_user(&user)? {
            // check if any user id of the cert has been certified by this ca (else skip)
            let (sig_from_ca, _) =
                oca.cert_check_certifications(&user_cert)?;
            if sig_from_ca.is_empty() {
                continue;
            }

            // Create entries for each user id that the CA has certified
            for u in sig_from_ca {
                if let Ok(Some(email)) = u.email() {
                    ukl.keys.push(Key {
                        fingerprint: user_cert.fingerprint.clone(),
                        name: user.name.clone(),
                        email: Some(email),
                        comment: None,
                        keyserver: None,
                    });
                }
            }
        }
    }

    let signer = Box::new(|text: &str| oca.sign_detached(text));

    // make a signed list object
    let skl = ukl.sign(signer)?;

    // Write keylist and signature to the filesystem
    let mut keylist = path.clone();
    keylist.push(KEYLIST_FILE);
    open_file(keylist, force)?.write_all(&skl.keylist.as_bytes().to_vec())?;

    let mut sigfile = path;
    sigfile.push(sigfile_name);
    open_file(sigfile, force)?.write_all(&skl.sig.as_bytes().to_vec())?;

    Ok(())
}

fn open_file(name: PathBuf, overwrite: bool) -> std::io::Result<File> {
    if overwrite {
        File::create(name)
    } else {
        OpenOptions::new().write(true).create_new(true).open(name)
    }
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
