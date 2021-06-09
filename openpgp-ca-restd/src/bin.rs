// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! REST Interface for OpenPGP CA.
//! This is an experimental API for use at FSFE.

#[macro_use]
extern crate rocket;

mod cert_info;
mod cli;
pub mod json;
mod process_certs;
mod restd;
pub mod util;

use cli::RestdCli;
use structopt::StructOpt;

#[launch]
fn rocket() -> rocket::Rocket {
    let cli = RestdCli::from_args();

    let db = RestdCli::from_args().database;

    match cli.cmd {
        cli::Command::Run => restd::run(db),
    }
}