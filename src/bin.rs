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

use structopt::StructOpt;

use chrono::offset::Utc;
use chrono::DateTime;

use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp::Pgp;

use failure::{self, Fallible};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "openpgp-ca",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    about = "OpenPGP CA is a tool for managing OpenPGP keys within organizations."
)]
struct Opt {
    #[structopt(
        name = "database",
        short = "d",
        long = "database",
        value_name = "filename"
    )]
    database: Option<String>,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
    //init           Initialize OpenPGP CA
    /// Manage CA
    Ca {
        #[structopt(subcommand)]
        cmd: CaCommand,
    },
    /// Manage Users
    User {
        #[structopt(subcommand)]
        cmd: UserCommand,
    },
    /// Manage Bridges
    Bridge {
        #[structopt(subcommand)]
        cmd: BridgeCommand,
    },
    /// WKD
    Wkd {
        #[structopt(subcommand)]
        cmd: WkdCommand,
    },
    //    /// Manage Directories
    //    Directory {
    //        #[structopt(subcommand)]
    //        cmd: DirCommand,
    //    },
    //    /// Manage key-profiles
    //    KeyProfile {},
}

#[derive(StructOpt, Debug)]
enum CaCommand {
    /// Create CA
    New {
        #[structopt(takes_value = true, help = "CA domain name")]
        domain: String,

        #[structopt(
            short = "n",
            long = "name",
            takes_value = true,
            help = "User Name"
        )]
        name: Option<String>,
    },
    /// Export CA public key
    Export,
    /// Import trust signature for CA Key
    ImportTsig {
        #[structopt(
            short = "f",
            long = "file",
            takes_value = true,
            help = "File that contains the tsigned CA Key"
        )]
        key_file: String,
    },
    /// Show CA
    Show,
}

#[derive(StructOpt, Debug)]
enum UserCommand {
    /// Add User (create new Key-Pair)
    Add {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[structopt(
            short = "n",
            long = "name",
            takes_value = true,
            help = "User Name"
        )]
        name: Option<String>,
    },

    /// Add Revocation Certificate
    AddRevocation {
        #[structopt(
            short = "r",
            long = "revocation-file",
            takes_value = true,
            help = "File that contains a revocation cert"
        )]
        revocation_file: String,
    },
    /// Bulk checks on Users
    Check {
        #[structopt(subcommand)]
        cmd: UserCheckSubcommand,
    },
    /// Import User (use existing Public Key)
    Import {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[structopt(
            short = "f",
            long = "key-file",
            takes_value = true,
            help = "File that contains the User's Public Key"
        )]
        key_file: String,

        #[structopt(
            short = "n",
            long = "name",
            takes_value = true,
            help = "User Name"
        )]
        name: Option<String>,

        #[structopt(
            short = "r",
            long = "revocation-file",
            takes_value = true,
            help = "File that contains the User's revocation cert"
        )]
        revocation_file: Option<String>,
    },
    /// Export User Public Key (bulk, if no email address is given)
    Export {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Email address"
        )]
        email: Option<String>,
    },
    /// List Users
    List,
    /// Apply a Revocation Certificate
    ApplyRevocation {
        #[structopt(
            short = "i",
            long = "id",
            takes_value = true,
            help = "Id of a revocation cert"
        )]
        id: i32,
    },
    /// Show Revocation Keys (if available)
    ShowRevocations {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Email address"
        )]
        email: String,
    },
}

#[derive(StructOpt, Debug)]
enum UserCheckSubcommand {
    /// Check user key expiry
    Expiry {
        #[structopt(
            short = "d",
            long = "days",
            takes_value = true,
            help = "Check for keys that expire within 'days' days"
        )]
        days: Option<u64>,
    },
    /// Check signatures and trust signatures on CA key
    Sigs,
}

#[derive(StructOpt, Debug)]
enum BridgeCommand {
    /// List Bridges
    List,
    /// Add New Bridge (sign existing remote CA Public Key)
    New {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Bridge remote Email"
        )]
        email: Option<String>,

        #[structopt(
            short = "f",
            long = "remote-key-file",
            takes_value = true,
            help = "File that contains the remote CA's Public Key"
        )]
        remote_key_file: String,

        #[structopt(
            short = "s",
            long = "scope",
            takes_value = true,
            help = "Scope for trust of this bridge (domainname)"
        )]
        scope: Option<String>,
    },
    /// Revoke Bridge
    Revoke {
        #[structopt(
            short = "e",
            long = "email",
            takes_value = true,
            help = "Bridge remote Email"
        )]
        email: String,
    },
}

#[derive(StructOpt, Debug)]
enum WkdCommand {
    /// Export WKD structure
    Export {
        #[structopt(
            takes_value = true,
            help = "Filesystem directory for WKD export"
        )]
        path: String,
    },
}

fn real_main() -> Fallible<()> {
    let opt = Opt::from_args();

    let db: Option<String> = opt.database;
    let mut ca = ca::Ca::new(db.as_deref());

    match opt.cmd {
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
        Command::User { cmd } => match cmd {
            UserCommand::Add { email, name } => {
                // TODO: key-profile?

                let email: Vec<&str> =
                    email.iter().map(String::as_str).collect();

                ca.usercert_new(name.as_deref(), &email[..])?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.add_revocation(&revocation_file)?
            }

            UserCommand::Check { cmd } => match cmd {
                UserCheckSubcommand::Expiry { days } => {
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
                match email {
                    Some(email) => {
                        for cert in ca.get_usercerts(&email)? {
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
            UserCommand::List => list_users(&ca)?,
            UserCommand::ShowRevocations { email } => {
                show_revocations(&ca, &email)?;
            }
            UserCommand::ApplyRevocation { id } => {
                let rev = ca.get_revocation_by_id(id)?;
                ca.apply_revocation(rev)?;
            }
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
                ca.export_wkd(&db_ca.domainname, Path::new(&path))?;
            }
        },
    }

    Ok(())
}

fn show_revocations(ca: &ca::Ca, email: &str) -> Fallible<()> {
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

fn list_bridges(ca: &ca::Ca) -> Fallible<()> {
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
) -> Fallible<()> {
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
