// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use clap::{AppSettings, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(
    name = "openpgp-ca",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    version,
    global_setting(AppSettings::DeriveDisplayOrder),
    about = "OpenPGP CA is a tool for managing OpenPGP keys within organizations."
)]
pub struct Cli {
    #[clap(name = "filename", short = 'd', long = "database")]
    pub database: Option<String>,

    #[clap(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage CA
    Ca {
        #[clap(subcommand)]
        cmd: CaCommand,
    },
    /// Manage Users
    User {
        #[clap(subcommand)]
        cmd: UserCommand,
    },
    /// Manage Bridges
    Bridge {
        #[clap(subcommand)]
        cmd: BridgeCommand,
    },
    /// WKD
    Wkd {
        #[clap(subcommand)]
        cmd: WkdCommand,
    },
    /// Keylist
    Keylist {
        #[clap(subcommand)]
        cmd: KeyListCommand,
    },
    /// Update
    Update {
        #[clap(subcommand)]
        cmd: UpdateCommand,
    },
    //    /// Manage Directories
    //    Directory {
    //        #[clap(subcommand)]
    //        cmd: DirCommand,
    //    },
    //    /// Manage key-profiles
    //    KeyProfile {}
}
#[derive(Subcommand)]
pub enum CardInitMode {
    /// Generate a new OpenPGP CA key on the host computer, import it to the card.
    ///
    /// This will print the generated OpenPGP CA private key to stdout, the operator need to
    /// safekeep that key.
    OnHost {},

    /// Generate a new OpenPGP CA key on the card.
    /// Caution: the private key material can not be backed up, or copied to a second card,
    /// in this mode!
    OnCard {},

    /// Initialize OpenPGP from an OpenPGP card with pre-loaded keys, and a matching public key file.
    Import {
        /// CA public key File
        public: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum Backend {
    Card {
        /// OpenPGP card ident
        ident: String,

        #[clap(subcommand)]
        initmode: CardInitMode,

        #[clap(
            short = 'P',
            long = "pinpad",
            help = "Enforce use of pinpad for PIN entry"
        )]
        pinpad: bool,
    },
}

#[derive(Subcommand)]
pub enum CaCommand {
    /// Create CA
    Init {
        #[clap(help = "CA domain name")]
        domain: String,

        #[clap(short = 'n', long = "name", help = "Descriptive User Name")]
        name: Option<String>,

        #[clap(subcommand)]
        backend: Option<Backend>,
    },
    /// Export CA public key
    Export,
    /// Generate a set of revocations for the CA key
    Revocations {
        #[clap(short = 'o', long = "output", help = "File to export to")]
        output: PathBuf,
    },

    /// Import trust signature for CA Key
    ImportTsig {
        #[clap(help = "File that contains the tsigned CA Key")]
        cert_file: PathBuf,
    },
    /// Show CA information
    Show,
    /// Print CA private key
    Private,

    /// Re-certify User IDs (e.g after CA key rotation)
    ReCertify {
        #[clap(
            short = 'p',
            long = "public-old",
            help = "A file that contains the old CA public key"
        )]
        pubkey_file_old: String,

        #[clap(
            short = 'v',
            long = "validity",
            help = "Validity of the new certifications in days",
            default_value = "365"
        )]
        validity_days: u64,
    },
}

#[derive(Subcommand)]
pub enum UserCommand {
    /// Add User (create new Key-Pair)
    Add {
        #[clap(
            short = 'e',
            long = "email",
            required = true,
            number_of_values = 1,
            multiple = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[clap(short = 'n', long = "name", help = "Descriptive User Name")]
        name: Option<String>,

        #[clap(
            short = 'm',
            long = "minimal",
            help = "Minimal output (for consumption by tools such as 'pass')"
        )]
        minimal: bool,
    },

    /// Add Revocation Certificate
    AddRevocation {
        #[clap(help = "File that contains a revocation cert")]
        revocation_file: PathBuf,
    },
    /// Bulk checks on Users
    Check {
        #[clap(subcommand)]
        cmd: UserCheckSubcommand,
    },
    /// Import User (use existing Public Key)
    Import {
        #[clap(
            short = 'e',
            long = "email",
            required = true,
            number_of_values = 1,
            multiple = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[clap(
            short = 'f',
            long = "key-file",
            help = "File that contains the User's Public Key"
        )]
        cert_file: PathBuf,

        #[clap(short = 'n', long = "name", help = "Descriptive User Name")]
        name: Option<String>,

        #[clap(
            short = 'r',
            long = "revocation-file",
            number_of_values = 1,
            multiple = true,
            help = "File that contains a revocation cert for this user"
        )]
        revocation_file: Vec<PathBuf>,
    },
    /// Update User (use existing Public Key)
    Update {
        #[clap(
            short = 'f',
            long = "key-file",
            help = "File that contains the User's Public Key"
        )]
        cert_file: PathBuf,
    },
    /// Export User Public Key (bulk, if no email address is given)
    Export {
        #[clap(short = 'e', long = "email", help = "Email address")]
        email: Option<String>,

        #[clap(short = 'p', long = "path", help = "Output path")]
        path: Option<String>,
    },
    /// List Users
    List,
    /// Apply a Revocation Certificate
    ApplyRevocation {
        #[clap(help = "Id of a revocation cert")]
        hash: String,
    },
    /// Show Revocation Certificates (if available)
    ShowRevocations {
        #[clap(short = 'e', long = "email", help = "Email address")]
        email: String,
    },
}

#[derive(Subcommand)]
pub enum UserCheckSubcommand {
    /// Check user key expiry
    Expiry {
        #[clap(
            short = 'd',
            long = "days",
            help = "Check for keys that expire within 'days' days",
            default_value = "30"
        )]
        days: u64,
    },
    /// Check certifications on CA key
    Certifications,
}

#[derive(Subcommand)]
pub enum BridgeCommand {
    /// List Bridges
    List,
    /// Export Bridge Public Key (bulk, if no domain name is given)
    Export {
        #[clap(help = "Remote CA Email address")]
        email: Option<String>,
    },

    /// Add New Bridge (certify existing remote CA Public Key)
    New {
        #[clap(short = 'e', long = "email", help = "Bridge remote Email")]
        email: Option<String>,

        #[clap(short = 'c', long = "commit", help = "Commit Bridge certification")]
        commit: bool,

        #[clap(help = "File that contains the remote CA's Public Key")]
        remote_key_file: PathBuf,

        #[clap(
            name = "domainname",
            short = 's',
            long = "scope",
            help = "Scope for trust of this bridge"
        )]
        scope: Option<String>,
    },
    /// Revoke Bridge
    Revoke {
        #[clap(short = 'e', long = "email", help = "Bridge remote Email")]
        email: String,
    },
}

#[derive(Subcommand)]
pub enum WkdCommand {
    /// Export WKD structure
    Export {
        #[clap(help = "Filesystem directory for WKD export")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum KeyListCommand {
    /// Export KeyList
    Export {
        #[clap(
            short = 'p',
            long = "path",
            help = "Filesystem directory for KeyList export"
        )]
        path: PathBuf,

        #[clap(short = 's', long = "sig-uri", help = "Sinature URI")]
        signature_uri: String,

        #[clap(
            short = 'f',
            long = "force",
            help = "Overwrite keylist/sig files if they exist"
        )]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum UpdateCommand {
    /// Update certificates from a keyserver
    Keyserver {},
    /// Update certificates from WKD
    Wkd {},
}
