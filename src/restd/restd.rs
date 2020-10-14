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

mod certinfo;
mod cli;
mod util;

use certinfo::CertInfo;

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
struct Certificate {
    email: Vec<String>,
    name: Option<String>,
    cert: String,
    revocations: Vec<String>,
    // doesn't need to be provided (default: false),
    // but will always be returned
    delisted: Option<bool>,
    // doesn't need to be provided (default: false),
    // but will always be returned
    inactive: Option<bool>,
}

/// A container for information about a Cert.
///
/// `cert_info` contains factual information about a cert.
///
/// Later we may add e.g. `cert_lints` (... ?)
#[derive(Debug, Serialize, Deserialize)]
struct ReturnJSON {
    cert_info: CertInfo,
    // later:
    // - cert_lints (e.g. expiry warnings, deprecated crypto, ...)
    action: Option<String>,
    // "new", "update" ?
    key: String, // the key, ascii armored
}

fn check_and_normalize_cert(
    ca: &OpenpgpCa,
    certificate: &Certificate,
) -> Result<Cert> {
    let mut cert = OpenpgpCa::armored_to_cert(&certificate.cert)
        .expect("Error while parsing the user-provided armored OpenPGP key");

    // private keys are illegal
    if cert.is_tsk() {
        return Err(anyhow::anyhow!(
            "ERROR: The user provided private key material"
        ));
    }

    // reject unreasonably big keys
    if certificate.cert.len() > KEY_SIZE_LIMIT {
        return Err(anyhow::anyhow!(
            "ERROR: User certificate is too long ({} bytes)",
            certificate.cert.len()
        ));
    }

    // get the domain of this CA
    let my_domain = ca
        .get_ca_domain()
        .expect("Error while getting the CA's domain");

    // split up user_ids between "external" and "internal" emails, then:
    let (int_provided, _) =
        util::split_emails(&my_domain, &certificate.email)?;

    let mut int_remaining: HashSet<_> = int_provided.iter().collect();
    let mut filter_uid = Vec::new();

    for user_id in cert.userids() {
        let email = user_id.email()?;
        if let Some(email) = email {
            if util::is_email_in_domain(&email, &my_domain)? {
                // a) all provided internal "email" entries must exist in cert user_ids
                if int_remaining.contains(&email) {
                    int_remaining.remove(&email);
                } else {
                    // b) flag additional "internal" emails for removal
                    filter_uid.push(user_id.userid().clone());
                }
            }
        }
    }

    // b) strip additional "internal"s user_ids from the Cert
    for filter in filter_uid {
        cert = util::user_id_filter(&cert, &filter)?;
    }

    if !int_remaining.is_empty() {
        // some provided internal "email" entries do not exist in user_ids
        // -> not ok!

        return Err(anyhow::anyhow!(
            "ERROR: User certificate does not contain user_ids for '{:?}'",
            int_remaining
        ));
    }

    Ok(cert)
}

#[get("/certs/list/<email>")]
fn list_certs(email: String) -> Json<Vec<ReturnJSON>> {
    let res: Result<Vec<ReturnJSON>> = CA.with(|ca| {
        let mut certificates = Vec::new();

        for c in ca.certs_get(&email)? {
            let cert = OpenpgpCa::armored_to_cert(&c.pub_cert)?;

            let r = ReturnJSON {
                cert_info: (&cert).into(),
                key: OpenpgpCa::cert_to_armored(&cert)?,
                action: None,
            };

            certificates.push(r);
        }

        Ok(certificates)
    });

    Json(res.unwrap())
}

/// Similar to "post_user", but doesn't commit data to DB.
///
/// Returns information about what the commit would result in.
#[get("/certs/check", data = "<certificate>", format = "json")]
fn check_cert(certificate: Json<Certificate>) -> Json<ReturnJSON> {
    CA.with(|ca| {
        let res = check_and_normalize_cert(&ca, &certificate.into_inner());

        // FIXME: do some more linting?

        if let Ok(cert) = res {
            // check if fingerprint exists in db
            // -> action "new" or "update"

            let fp = cert.fingerprint().to_hex();
            let res = ca.cert_get_by_fingerprint(&fp);
            if let Ok(cert_by_fp) = res {
                let action = if cert_by_fp.is_some() {
                    "update"
                } else {
                    "new"
                };

                let armor = OpenpgpCa::cert_to_armored(&cert);
                if let Ok(key) = armor {
                    Json(ReturnJSON {
                        cert_info: (&cert).into(),
                        key,
                        action: Some(action.to_string()),
                    })
                } else {
                    panic!(armor);
                }
            } else {
                panic!(res);
            }
        } else {
            panic!(res);
        }
    })
}

/// Store new User-Key data in the OpenPGP CA database.
///
/// This function is intended for the following workflows:
///
/// 1) add an entirely new user
/// 2) store an update for an existing key (i.e. same fingerprint)
/// 2a) one notable specific case of this:
///     the user adds a revocation to their key (as an update).
/// 3) store a "new" (i.e. different fingerprint) key for the same user
#[post("/certs", data = "<certificate>", format = "json")]
fn post_user(certificate: Json<Certificate>) {
    // let cert: Cert; // resulting Cert, after persisting (?)

    let res = CA.with(|ca| {
        let cert = certificate.into_inner();

        // check and normalize user-provided public key
        let cert_normalized = check_and_normalize_cert(ca, &cert)?;

        // check if a cert with this fingerprint exists already
        let fp = cert_normalized.fingerprint().to_hex();
        let cert_by_fp = ca.cert_get_by_fingerprint(&fp)?;

        if let Some(cert_by_fp) = cert_by_fp {
            // fingerprint of the key already exists
            //   -> merge data, update existing key
            let existing = OpenpgpCa::armored_to_cert(&cert_by_fp.pub_cert)?;

            let updated = existing.merge(cert_normalized)?;

            ca.cert_import_update(&OpenpgpCa::cert_to_armored(&updated)?)
        } else {
            // fingerprint doesn't exist yet -> new cert

            ca.cert_import_new(
                &OpenpgpCa::cert_to_armored(&cert_normalized)?,
                vec![],
                cert.name.as_deref(),
                cert.email
                    .iter()
                    .map(|e| e.deref())
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
        }
    });

    if res.is_err() {
        panic!(res);
    }
}

/// Mark a certificate as "deactivated".
/// It will continue to be listed and exported to WKD.
/// However, the certification by our CA will expire and not get renewed.
///
/// This approach is probably appropriate in most cases to phase out a
/// certificate.
#[post("/certs/deactivate/<fp>")]
fn deactivate_cert(fp: String) -> String {
    CA.with(|ca| {
        if let Ok(Some(mut cert)) = ca.cert_get_by_fingerprint(&fp) {
            cert.inactive = true;
            if ca.cert_update(&cert).is_err() {
                panic!("Couldn't update Cert in database");
            }
        } else {
            panic!("Couldn't get Cert by fingerprint {}", fp);
        }
    });

    "Cert deactivated".to_string()
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
    CA.with(|ca| {
        if let Ok(Some(mut cert)) = ca.cert_get_by_fingerprint(&fp) {
            cert.delisted = true;
            if ca.cert_update(&cert).is_err() {
                panic!("Couldn't update Cert in database");
            }
        } else {
            panic!("Couldn't get Cert by fingerprint {}", fp);
        }
    });

    "Cert delisted".to_string()
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
