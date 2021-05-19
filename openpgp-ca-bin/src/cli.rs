// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use clap::AppSettings;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "openpgp-ca",
author = "Heiko Schäfer <heiko@schaefer.name>",
global_settings(& [AppSettings::VersionlessSubcommands,
AppSettings::DisableHelpSubcommand, AppSettings::DeriveDisplayOrder]),
about = "OpenPGP CA is a tool for managing OpenPGP keys within organizations."
)]
pub struct Cli {
    #[structopt(name = "filename", short = "d", long = "database")]
    pub database: Option<String>,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
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
    /// Keylist
    Keylist {
        #[structopt(subcommand)]
        cmd: KeyListCommand,
    },
    /// Update
    Update {
        #[structopt(subcommand)]
        cmd: UpdateCommand,
    },
    //    /// Manage Directories
    //    Directory {
    //        #[structopt(subcommand)]
    //        cmd: DirCommand,
    //    },
    //    /// Manage key-profiles
    //    KeyProfile {}
}

#[derive(StructOpt, Debug)]
pub enum CaCommand {
    /// Create CA
    Init {
        #[structopt(help = "CA domain name")]
        domain: String,

        #[structopt(
            short = "n",
            long = "name",
            help = "Descriptive User Name"
        )]
        name: Option<String>,
    },
    /// Export CA public key
    Export,
    /// Generate a set of revocations for the CA key
    Revocations {
        #[structopt(short = "o", long = "output", help = "File to export to")]
        output: PathBuf,
    },

    /// Import trust signature for CA Key
    ImportTsig {
        #[structopt(help = "File that contains the tsigned CA Key")]
        cert_file: PathBuf,
    },
    /// Show CA
    Show,
}

#[derive(StructOpt, Debug)]
pub enum UserCommand {
    /// Add User (create new Key-Pair)
    Add {
        #[structopt(
            short = "e",
            long = "email",
            required = true,
            number_of_values = 1,
            multiple = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[structopt(
            short = "n",
            long = "name",
            help = "Descriptive User Name"
        )]
        name: Option<String>,

        #[structopt(
            short = "m",
            long = "minimal",
            help = "Minimal output (for consumption by tools such as 'pass')"
        )]
        minimal: bool,
    },

    /// Add Revocation Certificate
    AddRevocation {
        #[structopt(help = "File that contains a revocation cert")]
        revocation_file: PathBuf,
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
            required = true,
            number_of_values = 1,
            multiple = true,
            help = "Email address"
        )]
        email: Vec<String>,

        #[structopt(
            short = "f",
            long = "key-file",
            help = "File that contains the User's Public Key"
        )]
        cert_file: PathBuf,

        #[structopt(
            short = "n",
            long = "name",
            help = "Descriptive User Name"
        )]
        name: Option<String>,

        #[structopt(
            short = "r",
            long = "revocation-file",
            number_of_values = 1,
            multiple = true,
            help = "File that contains a revocation cert for this user"
        )]
        revocation_file: Vec<PathBuf>,
    },
    /// Export User Public Key (bulk, if no email address is given)
    Export {
        #[structopt(short = "e", long = "email", help = "Email address")]
        email: Option<String>,

        #[structopt(short = "p", long = "path", help = "Output path")]
        path: Option<String>,
    },
    /// List Users
    List,
    /// Apply a Revocation Certificate
    ApplyRevocation {
        #[structopt(help = "Id of a revocation cert")]
        hash: String,
    },
    /// Show Revocation Certificates (if available)
    ShowRevocations {
        #[structopt(short = "e", long = "email", help = "Email address")]
        email: String,
    },
}

#[derive(StructOpt, Debug)]
pub enum UserCheckSubcommand {
    /// Check user key expiry
    Expiry {
        #[structopt(
            short = "d",
            long = "days",
            help = "Check for keys that expire within 'days' days",
            default_value = "30"
        )]
        days: u64,
    },
    /// Check certifications on CA key
    Certifications,
}

#[derive(StructOpt, Debug)]
pub enum BridgeCommand {
    /// List Bridges
    List,
    /// Export Bridge Public Key (bulk, if no domain name is given)
    Export {
        #[structopt(help = "Remote CA Email address")]
        email: Option<String>,
    },

    /// Add New Bridge (certify existing remote CA Public Key)
    New {
        #[structopt(
            short = "e",
            long = "email",
            help = "Bridge remote Email"
        )]
        email: Option<String>,

        #[structopt(
            short = "c",
            long = "commit",
            help = "Commit Bridge certification"
        )]
        commit: bool,

        #[structopt(help = "File that contains the remote CA's Public Key")]
        remote_key_file: PathBuf,

        #[structopt(
            name = "domainname",
            short = "s",
            long = "scope",
            help = "Scope for trust of this bridge"
        )]
        scope: Option<String>,
    },
    /// Revoke Bridge
    Revoke {
        #[structopt(
            short = "e",
            long = "email",
            help = "Bridge remote Email"
        )]
        email: String,
    },
}

#[derive(StructOpt, Debug)]
pub enum WkdCommand {
    /// Export WKD structure
    Export {
        #[structopt(help = "Filesystem directory for WKD export")]
        path: PathBuf,
    },
}

#[derive(StructOpt, Debug)]
pub enum KeyListCommand {
    /// Export KeyList
    Export {
        #[structopt(
            short = "p",
            long = "path",
            help = "Filesystem directory for KeyList export"
        )]
        path: PathBuf,

        #[structopt(short = "s", long = "sig-uri", help = "Sinature URI")]
        signature_uri: String,

        #[structopt(
            short = "f",
            long = "force",
            help = "Overwrite keylist/sig files if they exist"
        )]
        force: bool,
    },
}

#[derive(StructOpt, Debug)]
pub enum UpdateCommand {
    /// Update certificates from a keyserver
    Keyserver {},
    /// Update certificates from WKD
    Wkd {},
}
