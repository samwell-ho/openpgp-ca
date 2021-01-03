// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! REST Interface for OpenPGP CA.
//! This is an experimental API for use at FSFE.

use once_cell::sync::OnceCell;
use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;

use crate::ca::OpenpgpCa;
use crate::models;
use crate::restd::oca_json::*;
use crate::restd::process_certs::{cert_to_cert_info, process_certs};

mod cli;
mod process_certs;
mod util;

pub mod cert_info;
pub mod client;
pub mod oca_json;

static DB: OnceCell<Option<String>> = OnceCell::new();

thread_local! {
    static CA: OpenpgpCa = OpenpgpCa::new(DB.get().unwrap().as_deref())
        .expect("OpenPGP CA new() failed - database problem?");
}

// CA certifications are good for 365 days
const CERTIFICATION_DAYS: u64 = 365;

// armored cert size limit (1 MiB)
const CERT_SIZE_LIMIT: usize = 1024 * 1024;

// FIXME
// links for information about bad certificates - and what to do about them
const POLICY_BAD_URL: &str = "https://very-bad-cert.example.org";
const POLICY_SHA1_BAD_URL: &str = "https://bad-cert-with-sha1.example.org";

pub fn load_certificate_data(
    ca: &OpenpgpCa,
    cert: &models::Cert,
) -> Result<Certificate, ReturnError> {
    let res = {
        let user =
            ca.cert_get_users(&cert)
                .map_err(|e| {
                    ReturnError::new(
                        ReturnStatus::InternalError,
                        format!(
                            "load_certificate_data: error while loading users \
                        '{:?}'", e
                        ),
                    )
                })?
                .unwrap();

        let emails = ca.emails_get(&cert).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!(
                    "load_certificate_data: error while loading emails '{:?}'",
                    e
                ),
            )
        })?;

        let rev = ca.revocations_get(&cert).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!(
                    "load_certificate_data: error while loading revocations\
                     '{:?}'",
                    e
                ),
            )
        })?;

        Certificate::from(&cert, &user, &emails, &rev)
    };

    Ok(res)
}

#[get("/certs/by_email/<email>")]
fn certs_by_email(
    email: String,
) -> Result<Json<Vec<ReturnGoodJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let mut res = Vec::new();

        let certs = ca.certs_get(&email).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!(
                    "certs_by_email: error loading certificates data '{:?}'",
                    e
                ),
            )
        })?;

        for c in certs {
            let cert =
                OpenpgpCa::armored_to_cert(&c.pub_cert).map_err(|e| {
                    ReturnError::new(
                        ReturnStatus::InternalError,
                        format!(
                            "certs_by_email: error during armored_to_cert \
                            '{:?}'",
                            e
                        ),
                    )
                })?;

            let cert_info = cert_to_cert_info(&cert)?;

            let certificate = load_certificate_data(&ca, &c)?;

            let r = ReturnGoodJSON {
                cert_info,
                action: None,
                upload: None,
                certificate,
            };
            res.push(r);
        }

        Ok(Json(res))
    })
}

#[get("/certs/by_fp/<fp>")]
fn certs_by_fp(
    fp: String,
) -> Result<Json<Option<ReturnGoodJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let c = ca.cert_get_by_fingerprint(&fp).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!(
                    "certs_by_fp: error loading certificate data '{:?}'",
                    e
                ),
            )
        })?;

        if let Some(c) = c {
            let cert =
                OpenpgpCa::armored_to_cert(&c.pub_cert).map_err(|e| {
                    ReturnError::new(
                        ReturnStatus::InternalError,
                        format!(
                            "certs_by_fp: error during armored_to_cert '{:?}'",
                            e
                        ),
                    )
                })?;

            let certificate = load_certificate_data(&ca, &c)?;

            let cert_info = cert_to_cert_info(&cert)?;

            Ok(Json(Some(ReturnGoodJSON {
                cert_info,
                certificate,
                action: None,
                upload: None,
            })))
        } else {
            Ok(Json(None))
        }
    })
}

/// Similar to "post_user", but doesn't commit data to DB.
///
/// Returns information about what the commit would result in.
#[get("/certs/check", data = "<certificate>", format = "json")]
fn check_certs(
    certificate: Json<Certificate>,
) -> Result<Json<Vec<CertResultJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        Ok(Json(process_certs(&ca, &certificate.into_inner(), false)?))
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
fn post_certs(
    certificate: Json<Certificate>,
) -> Result<Json<Vec<CertResultJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        Ok(Json(process_certs(&ca, &certificate.into_inner(), true)?))
    })
}

/// Mark a certificate as "deactivated".
/// It will continue to be listed and exported to WKD.
/// However, the certification by our CA will expire and not get renewed.
///
/// This approach is probably appropriate in most cases to phase out a
/// certificate.
#[post("/certs/deactivate/<fp>")]
fn deactivate_cert(fp: String) -> Result<(), BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let cert = ca.cert_get_by_fingerprint(&fp).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.inactive = true;

            ca.cert_update(&cert).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("Error updating Cert '{:?}'", e),
                )
            })?;
        } else {
            return Err(ReturnError::new(
                ReturnStatus::NotFound,
                format!("Fingerprint '{}' not found", fp),
            )
            .into());
        }

        Ok(())
    })
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
fn delist_cert(fp: String) -> Result<(), BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let cert = ca.cert_get_by_fingerprint(&fp).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.delisted = true;

            ca.cert_update(&cert).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("Error updating Cert '{:?}'", e),
                )
            })?;
        } else {
            return Err(ReturnError::new(
                ReturnStatus::NotFound,
                format!("Fingerprint '{}' not found", fp),
            )
            .into());
        }

        Ok(())
    })
}

/// Refresh CA certifications on all user certs
///
/// For certifications which are going to expire soon:
/// Make a new certification, unless the user cert is marked as "deactivated".
#[post("/refresh_ca_certifications")]
fn refresh_certifications() -> Result<(), BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        ca.certs_refresh_ca_certifications(30, CERTIFICATION_DAYS)
            .map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!(
                        "Error during certs_refresh_ca_certifications '{:?}'",
                        e
                    ),
                )
            })?;

        Ok(())
    })
}

/// Poll for updates to user keys (e.g. on https://keys.openpgp.org/)
#[post("/poll_updates")]
fn poll_for_updates() -> String {
    unimplemented!()
}

pub fn run(db: Option<String>) -> rocket::Rocket {
    DB.set(db).unwrap();

    rocket::ignite().mount(
        "/",
        routes![
            certs_by_email,
            certs_by_fp,
            check_certs,
            post_certs,
            deactivate_cert,
            delist_cert,
            refresh_certifications,
            poll_for_updates,
        ],
    )
}
