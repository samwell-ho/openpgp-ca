// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use structopt::StructOpt;

pub mod cli;

use cli::*;
use openpgp_ca_lib::ca::OpenpgpCa;

fn main() -> Result<()> {
    let cli = Cli::from_args();

    let ca = OpenpgpCa::new(cli.database.as_deref())?;

    match cli.cmd {
        Command::User { cmd } => match cmd {
            UserCommand::Add {
                email,
                name,
                minimal,
            } => {
                // TODO: key-profile?

                let emails: Vec<_> =
                    email.iter().map(String::as_str).collect();

                ca.user_new(
                    name.as_deref(),
                    &emails[..],
                    None,
                    true,
                    minimal,
                )?;
            }
            UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add_from_file(&revocation_file)?
            }

            UserCommand::Check { cmd } => match cmd {
                UserCheckSubcommand::Expiry { days } => {
                    OpenpgpCa::print_expiry_status(&ca, days)?;
                }
                UserCheckSubcommand::Certifications => {
                    OpenpgpCa::print_certifications_status(&ca)?;
                }
            },
            UserCommand::Import {
                cert_file,
                name,
                email,
                revocation_file,
            } => {
                let cert = std::fs::read_to_string(cert_file)?;

                let mut revoc_certs = Vec::new();
                for path in revocation_file {
                    let rev = std::fs::read_to_string(path)?;
                    revoc_certs.push(rev);
                }

                let emails: Vec<_> =
                    email.iter().map(String::as_str).collect();

                ca.cert_import_new(
                    &cert,
                    revoc_certs,
                    name.as_deref(),
                    &emails,
                    None,
                )?;
            }
            UserCommand::Export { email, path } => {
                if let Some(path) = path {
                    ca.export_certs_as_files(email, &path)?;
                } else {
                    ca.print_certring(email)?;
                }
            }
            UserCommand::List => OpenpgpCa::print_users(&ca)?,
            UserCommand::ShowRevocations { email } => {
                OpenpgpCa::print_revocations(&ca, &email)?
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
                println!("{}", ca.ca_get_pubkey_armored()?);
            }
            CaCommand::Revocations { output } => {
                ca.ca_generate_revocations(output)?;
                println!("Wrote a set of revocations to the output file");
            }
            CaCommand::ImportTsig { cert_file } => {
                let cert = std::fs::read_to_string(cert_file)?;
                ca.ca_import_tsig(&cert)?;
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
                ca.export_wkd(&ca.get_ca_domain()?, &path)?;
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
        Command::Update { cmd } => match cmd {
            UpdateCommand::Keyserver {} => ca.update_from_keyserver()?,
        },
    }

    Ok(())
}
