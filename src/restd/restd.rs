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
pub mod util;

use anyhow::Result;
use cli::RestdCli;
use structopt::StructOpt;

use std::collections::HashSet;

use openpgp::Cert;
use sequoia_openpgp as openpgp;

use openpgp_ca_lib::ca::OpenpgpCa;

thread_local! {
    static CA: OpenpgpCa = OpenpgpCa::new(RestdCli::from_args().database.as_deref())
        .expect("OpenPGP CA new() failed - database problem?");
}

// key size limit (armored): 1 mbyte
const KEY_SIZE_LIMIT: usize = 1024 * 1024;

/// REST Interface for OpenPGP CA.
/// This is an experimental API for use at FSFE.
#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: Vec<String>,
    name: Option<String>,
    cert: String,
    revocations: Vec<String>,
}

/// Human-readable information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize)]
struct CertJSON {
    fingerprint: String,
    user_ids: Vec<String>,
}

fn check_and_normalize_cert(ca: &OpenpgpCa, user: &User) -> Result<Cert> {
    let mut cert = OpenpgpCa::armored_to_cert(&user.cert)
        .expect("Error while parsing the user-provided armored OpenPGP key");

    // private keys are illegal
    if cert.is_tsk() {
        return Err(anyhow::anyhow!(
            "ERROR: The user provided private key material"
        ));
    }

    // reject unreasonably big keys
    if user.cert.len() > KEY_SIZE_LIMIT {
        return Err(anyhow::anyhow!(
            "ERROR: User certificate is too long ({} bytes)",
            user.cert.len()
        ));
    }

    // get the domain of this CA
    let my_domain = ca
        .get_ca_domain()
        .expect("Error while getting the CA's domain");

    // split up user_ids between "external" and "internal" emails, then:
    let (int_provided, ext_provided) =
        util::split_emails(&my_domain, &user.email)?;

    let mut int_remaining: HashSet<_> = int_provided.iter().collect();

    for user_id in cert.userids() {
        let email = user_id.email()?;
        if let Some(email) = email {
            if util::is_email_in_domain(&email, &my_domain)? {
                // a) all provided internal "email" entries must exist in cert user_ids
                if int_remaining.contains(&email) {
                    int_remaining.remove(&email);
                } else {
                    // b) additional "internal" emails the key's user_ids must be stripped
                    unimplemented!();
                }
            }
        }
    }

    if !int_remaining.is_empty() {
        // some provided internal "email" entries do not exist in user_ids
        // -> not ok!

        return Err(anyhow::anyhow!(
            "ERROR: User certificate does not contain user_ids for '{:?}'",
            int_remaining
        ));
        panic!();
    }

    Ok(cert)
}

#[get("/certs/<email>")]
fn list_certs(email: String) -> Json<Vec<CertJSON>> {
    let res: Result<Vec<CertJSON>> = CA.with(|ca| {
        let mut certificates = Vec::new();

        for c in ca.certs_get(&email)? {
            let cert = OpenpgpCa::armored_to_cert(&c.pub_cert)?;

            let emails = cert
                .userids()
                .filter_map(|uid| {
                    uid.email().expect("ERROR while converting user_id")
                })
                .collect();

            let cert_json = CertJSON {
                fingerprint: cert.fingerprint().to_hex(),
                user_ids: emails,
            };

            certificates.push(cert_json);
        }

        Ok(certificates)
    });

    Json(res.unwrap())
}

/// Similar to "post_user", but doesn't commit data to DB.
///
/// Returns information about what the commit would result in.
#[post("/users/check", data = "<user>", format = "json")]
fn check_cert(user: Json<User>) -> Json<CertJSON> {
    // "the user clicks submit
    // the certificates are summarized
    // and then the user gets another chance to click accept or reject
    // when viewing the certificates, the web panel needs to query openpgp ca and say: give me the data for this user
    // then they are summarized in the previous fashion
    // the web panel db should not try and save the openpgp certificates"

    // "the preview prevents the user from publishing incorrect data
    // it is also a point where we can display some lints
    // and warnings (like: you uploaded a private key! your key is
    // invalid because it uses sha-1!)"

    unimplemented!()
}

/// Store new User-Key data in the OpenPGP CA database.
///
/// This function is intended for the following workflows:
///
/// 1) add an entirely new user
/// 2) store an update for an existing key (i.e. same fingerprint)
/// 2a) one specific case of this:
///     the user adds a revocation to their key, as an update.
/// 3) store a "new" (i.e. different fingerprint) key for the same user
#[post("/certs", data = "<user>", format = "json")]
fn post_user(user: Json<User>) -> String {
    let res = CA.with(|ca| {
        let user = user.into_inner();

        // check and normalize user-provided public key
        let cert_new = check_and_normalize_cert(ca, &user)?;

        // find only the "internal" emails from user.email
        // - get the domain of this CA
        let my_domain = ca
            .get_ca_domain()
            .expect("Error while getting the CA domain");

        // - split up user_ids between "external" and "internal" emails, then:
        let (internal_emails, external) =
            util::split_emails(&my_domain, &user.email)?;

        // get existing Certs for this email from the CA DB
        let mut certs: Vec<_> = Vec::new();
        for email in &internal_emails {
            certs.append(&mut ca.certs_get(email)?);
        }

        if certs.is_empty() {
            // 1. the "internal" email/userid doesn't exist in O-CA yet
            // -> new user

            ca.cert_import_new(
                &OpenpgpCa::cert_to_armored(&cert_new)?,
                vec![],
                user.name.as_deref(),
                user.email
                    .iter()
                    .map(|e| e.deref())
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
        } else {
            // 2. the "internal" email/userid exist in OpenPGP CA already

            // check if a cert with this fingerprint exists already
            let fp = cert_new.fingerprint().to_hex();

            if let Some(exist_cert) = ca.cert_get_by_fingerprint(&fp)? {
                let cert_exist =
                    OpenpgpCa::armored_to_cert(&exist_cert.pub_cert)?;

                let update = cert_exist.merge(cert_new)?;

                //   2a. fingerprint of the key already exists
                //   (-> updated version of this key -> merge)

                //     -> update existing key, merge data

                ca.cert_import_update(&OpenpgpCa::cert_to_armored(&update)?)
            } else {
                //   2b. fingerprint doesn't exist -> new key for existing user

                //     - add a new entry

                //     - what should we do with the old key?

                unimplemented!()
            }
        }
    });

    // FIXME: error handling?

    // Return fingerprint as potential database key?!

    // FIXME: output?
    format!("Result: {:?}\n", res)
}

/// Mark a certificate as "deactivated".
/// It will continue to be listed and exported to WKD.
/// However, the certification by our CA will expire and not get renewed.
///
/// This approach is probably appropriate in most cases to phase out a
/// certificate.
#[post("/certs/deactivate/<fp>")]
fn deactivate_cert(fp: String) -> String {
    unimplemented!()
}

/// Remove a cert from the OpenPGP CA database, by fingerprint.
/// As a result, the cert will not be exported to WKD anymore.
///
/// Note: the CA certification will not get renewed in this case, so it will
/// expire.
///
/// CAUTION:
/// This method is probably rarely appropriate. In most cases, it's better
/// to "deactivate" a cert.
#[delete("/certs/<fp>")]
fn delist_cert(fp: String) -> String {
    unimplemented!();
}

/// Refresh CA certifications on all user certs
///
/// For certifications which are going to expire soon:
/// Make a new certification, unless the user cert is marked as "deactivated".
#[post("/refresh_ca_certifications")]
fn refresh_certifications() -> String {
    unimplemented!()
}

/// Poll for updates to user keys (e.g. on https://keys.openpgp.org/)
#[post("/poll_updates")]
fn poll_for_updates() -> String {
    unimplemented!()
}

#[launch]
fn rocket() -> rocket::Rocket {
    use cli::Command;

    let cli = RestdCli::from_args();
    match cli.cmd {
        Command::Run => rocket::ignite().mount(
            "/",
            routes![
                list_certs,
                check_cert,
                post_user,
                deactivate_cert,
                delist_cert,
                refresh_certifications,
                poll_for_updates
            ],
        ),
    }
}
