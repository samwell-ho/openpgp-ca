// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::{anyhow, Result};
use clap::{CommandFactory, FromArgMatches};

use openpgp_ca_lib::ca::{OpenpgpCa, OpenpgpCaUninit};

mod cli;

fn main() -> Result<()> {
    let version = format!(
        "{} (openpgp-ca-lib {})",
        env!("CARGO_PKG_VERSION"),
        openpgp_ca_lib::VERSION,
    );

    let cli = cli::Cli::command().version(&*version);

    let c = cli::Cli::from_arg_matches(&cli.get_matches())?;

    let cau = OpenpgpCaUninit::new(c.database.as_deref())?;

    // Handle init calls separately, here.
    // Setting up an OpenpgpCa instance differs from all other workflows.
    if let cli::Commands::Ca {
        cmd:
            cli::CaCommand::Init {
                domain,
                name,
                backend,
            },
    } = &c.cmd
    {
        let ca = match backend {
            None => cau.ca_init(domain, name.as_deref()),
            Some(cli::Backend::Card {
                ident,
                pubkey,
                generate,
                on_card,
                pinpad,
            }) => {
                // FIXME: move all business logic from here to openpgp-ca-lib, later

                if *pinpad {
                    // FIXME:
                    // - extend syntax in database backend field: don't store PIN in pinpad mode
                    // - use pinpad for changing user PIN to its new value
                    // - use pinpad for signing operations

                    unimplemented!("pinpad mode is not implemented yet");
                }

                // Handle different setup modes
                if *generate {
                    // 1) generate key in CA, import to card, print encrypted private key+PW

                    // // check that card has no keys on it
                    // if !card::check_card_empty(ident)? {
                    //     return Err(anyhow!("The OpenPGP card contains key material, please reset it before use with OpenPGP CA."));
                    // }

                    // let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

                    unimplemented!()
                } else if *on_card {
                    // 2) generate key on card, make public key, print it (also: stored in DB)
                    let (ca, user_pin) = cau.ca_init_generate_on_card(ident, domain)?;

                    println!();
                    println!(
                        "NOTE: The User PIN for this OpenPGP card has been set to {}",
                        user_pin
                    );
                    println!();

                    // FIXME: Show sample opgpcard command CLI call to change Admin PIN in CA Docs.
                    // Explain difference between Gnuk and other cards:
                    // - Gnuk Admin PIN is now by default same as new User PIN.
                    // - Other cards have Admin PIN `12345678` after ca_init_generate_on_card().

                    Ok(ca)
                } else if pubkey.is_some() {
                    // 3) import existing card/key pair for init
                    let cert = if let Some(pubkey) = pubkey {
                        std::fs::read(pubkey)?
                    } else {
                        unimplemented!() // error out
                    };

                    unimplemented!()

                    // let ca_cert =
                    //     Pgp::to_cert(&cert).context("ca_init_card: Couldn't process CA cert.")?;
                    //
                    // cau.ca_init_card(ident, pin, domain, &ca_cert)
                } else {
                    // user didn't indicate how to initialize
                    Err(anyhow!("A mode of card initialization must be selected"))
                }
            }
        }?;

        println!("Created OpenPGP CA instance:");
        ca.ca_show()?;

        return Ok(());
    }

    // the CLI command was not `ca init`, so we should be able to get an OpenpgpCa object now
    let ca = cau.init_from_db_state()?;

    match c.cmd {
        cli::Commands::User { cmd } => match cmd {
            cli::UserCommand::Add {
                email,
                name,
                minimal,
            } => {
                // TODO: key-profile?

                let emails: Vec<_> = email.iter().map(String::as_str).collect();

                ca.user_new(name.as_deref(), &emails[..], None, true, minimal)?;
            }
            cli::UserCommand::AddRevocation { revocation_file } => {
                ca.revocation_add_from_file(&revocation_file)?
            }

            cli::UserCommand::Check { cmd } => match cmd {
                cli::UserCheckSubcommand::Expiry { days } => {
                    OpenpgpCa::print_expiry_status(&ca, days)?;
                }
                cli::UserCheckSubcommand::Certifications => {
                    OpenpgpCa::print_certifications_status(&ca)?;
                }
            },
            cli::UserCommand::Import {
                cert_file,
                name,
                email,
                revocation_file,
            } => {
                let cert = std::fs::read(cert_file)?;

                let mut revoc_certs = Vec::new();
                for path in revocation_file {
                    let rev = std::fs::read(path)?;
                    revoc_certs.push(rev);
                }

                let emails: Vec<_> = email.iter().map(String::as_str).collect();

                ca.cert_import_new(
                    &cert,
                    revoc_certs
                        .iter()
                        .map(|v| v.as_slice())
                        .collect::<Vec<_>>()
                        .as_ref(),
                    name.as_deref(),
                    &emails,
                    None,
                )?;
            }
            cli::UserCommand::Update { cert_file } => {
                let cert = std::fs::read(cert_file)?;
                ca.cert_import_update(&cert)?;
            }
            cli::UserCommand::Export { email, path } => {
                if let Some(path) = path {
                    ca.export_certs_as_files(email, &path)?;
                } else {
                    ca.print_certring(email)?;
                }
            }
            cli::UserCommand::List => OpenpgpCa::print_users(&ca)?,
            cli::UserCommand::ShowRevocations { email } => {
                OpenpgpCa::print_revocations(&ca, &email)?
            }
            cli::UserCommand::ApplyRevocation { hash } => {
                let rev = ca.revocation_get_by_hash(&hash)?;
                ca.revocation_apply(rev)?;
            }
        },
        cli::Commands::Ca { cmd } => match cmd {
            cli::CaCommand::Init { .. } => {
                // handled separately, above
                unreachable!()
            }
            cli::CaCommand::Export => {
                println!("{}", ca.ca_get_pubkey_armored()?);
            }
            cli::CaCommand::Revocations { output } => {
                ca.ca_generate_revocations(output)?;
                println!("Wrote a set of revocations to the output file");
            }
            cli::CaCommand::ImportTsig { cert_file } => {
                let cert = std::fs::read(cert_file)?;
                ca.ca_import_tsig(&cert)?;
            }
            cli::CaCommand::Show => ca.ca_show()?,
            cli::CaCommand::Private => ca.ca_print_private()?,

            cli::CaCommand::ReCertify {
                pubkey_file_old: cert_file_old,
                validity_days,
            } => {
                let cert_old = std::fs::read(cert_file_old)?;
                ca.ca_re_certify(&cert_old, validity_days)?;
            }
        },
        cli::Commands::Bridge { cmd } => match cmd {
            cli::BridgeCommand::New {
                email,
                scope,
                remote_key_file,
                commit,
            } => ca.add_bridge(
                email.as_deref(),
                &remote_key_file,
                scope.as_deref(),
                false,
                commit,
            )?,
            cli::BridgeCommand::Revoke { email } => ca.bridge_revoke(&email)?,
            cli::BridgeCommand::List => ca.list_bridges()?,
            cli::BridgeCommand::Export { email } => ca.print_bridges(email)?,
        },
        cli::Commands::Wkd { cmd } => match cmd {
            cli::WkdCommand::Export { path } => {
                ca.export_wkd(&ca.get_ca_domain()?, &path)?;
            }
        },

        cli::Commands::Keylist { cmd } => match cmd {
            cli::KeyListCommand::Export {
                path,
                signature_uri,
                force,
            } => {
                ca.export_keylist(path, signature_uri, force)?;
            }
        },
        cli::Commands::Update { cmd } => match cmd {
            cli::UpdateCommand::Keyserver {} => ca.update_from_keyserver()?,
            cli::UpdateCommand::Wkd {} => ca.update_from_wkd()?,
        },
    }

    Ok(())
}
