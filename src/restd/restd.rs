// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ops::Deref;

#[macro_use]
extern crate rocket;

use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

pub mod cli;

use cli::RestdCli;
use structopt::StructOpt;

use openpgp_ca_lib::ca::OpenpgpCa;

thread_local! {
    static CA: OpenpgpCa = OpenpgpCa::new(RestdCli::from_args().database.as_deref())
        .expect("OpenPGP CA new() failed - database problem?");
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: Vec<String>,
    name: Option<String>,
    key: String,
}

// "Do you name your URL objects you create explicitly, or let the server
// decide? If you name them then use PUT. If you let the server decide then
// use POST."
#[post("/users/new", data = "<user>", format = "json")]
fn post_user_new(user: Json<User>) -> String {
    let res = CA.with(|ca| {
        let user = user.into_inner();

        ca.cert_import_new(
            &user.key,
            vec![],
            user.name.as_deref(),
            user.email
                .iter()
                .map(|e| e.deref())
                .collect::<Vec<_>>()
                .as_slice(),
        )
    });

    // FIXME: error handling?

    // Return fingerprint as potential database key?!

    format!("Result: {:?}\n", res)
}

#[launch]
fn rocket() -> rocket::Rocket {
    use cli::Command;

    let cli = RestdCli::from_args();
    match cli.cmd {
        Command::Run => rocket::ignite().mount("/", routes![post_user_new]),
    }
}
