// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! REST Interface for OpenPGP CA.
//! This is an experimental API for use at FSFE.

use std::convert::TryInto;

use once_cell::sync::OnceCell;
use openpgp_ca_lib::db::models;
use openpgp_ca_lib::pgp;
use openpgp_ca_lib::Oca;
use rocket::http::Status;
use rocket::response::status::BadRequest;
use rocket::serde::json::Json;
use rocket::Build;

use crate::cert_info::CertInfo;
use crate::json::*;
use crate::process_certs::{get_cert_info, get_warnings, process_certs};

static DB: OnceCell<Option<String>> = OnceCell::new();

thread_local! {
    static CA: Oca = Oca::open(DB.get().unwrap().as_deref())
        .expect("OpenpgpCaUninit new() failed - database problem?");
}

// CA certifications are good for 365 days
pub const CERTIFICATION_DAYS: u64 = 365;

// armored cert size limit (1 MiB)
pub const CERT_SIZE_LIMIT: usize = 1024 * 1024;

// FIXME: link for information about bad certificates
// - and what to do about them
// const POLICY_BAD_URL: &str = "https://very-bad-cert.example.org";

/// Load all of the associated data for a Cert from the CA database
fn load_certificate_data(ca: &Oca, cert: &models::Cert) -> Result<Certificate, ReturnError> {
    let user = ca.cert_get_users(cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("load_certificate_data: error while loading users '{:?}'", e),
        )
    })?;

    if user.is_none() {
        return Err(ReturnError::new(
            ReturnStatus::InternalError,
            "load_certificate_data: not found while loading users'".to_string(),
        ));
    }

    let emails = ca.emails_get(cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!(
                "load_certificate_data: error while loading emails '{:?}'",
                e
            ),
        )
    })?;

    let rev = ca.revocations_get(cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!(
                "load_certificate_data: error while loading revocations\
                     '{:?}'",
                e
            ),
        )
    })?;

    Ok(Certificate::from(cert, &user.unwrap(), &emails, &rev))
}

#[get("/certs/by_email/<email>")]
fn certs_by_email(
    email: String,
) -> Result<Json<Vec<ReturnGoodJson>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let mut res = Vec::new();

        let certs = ca.certs_by_email(&email).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("certs_by_email: error loading certs from db '{:?}'", e),
            )
        })?;

        for c in certs {
            let cert = pgp::to_cert(c.pub_cert.as_bytes()).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!(
                        "certs_by_email: error during armored_to_cert \
                            '{:?}'",
                        e
                    ),
                )
            })?;

            let cert_info = get_cert_info(&cert)?;
            let warn = get_warnings(&cert).map_err(|ce| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("certs_by_email: error during cert_to_warn '{:?}'", ce),
                )
            })?;

            let certificate = load_certificate_data(ca, &c)?;

            res.push(ReturnGoodJson {
                certificate,
                cert_info,
                warn,
                action: None,
                upload: None,
            });
        }

        Ok(Json(res))
    })
}

#[get("/certs/by_fp/<fp>")]
fn cert_by_fp(fp: String) -> Result<Json<Option<ReturnGoodJson>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let c = ca.cert_get_by_fingerprint(&fp).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("cert_by_fp: error loading certs from db '{:?}'", e),
            )
        })?;

        if let Some(c) = c {
            let certificate = load_certificate_data(ca, &c)?;

            let cert = pgp::to_cert(c.pub_cert.as_bytes()).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("cert_by_fp: error during armored_to_cert '{:?}'", e),
                )
            })?;

            let cert_info = get_cert_info(&cert)?;
            let warn = get_warnings(&cert).map_err(|ce| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("cert_by_fp: error during cert_to_warn '{:?}'", ce),
                )
            })?;

            Ok(Json(Some(ReturnGoodJson {
                certificate,
                cert_info,
                warn,
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
) -> Result<Json<Vec<CertResultJson>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| Ok(Json(process_certs(ca, &certificate.into_inner(), false)?)))
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
) -> Result<Json<Vec<CertResultJson>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| Ok(Json(process_certs(ca, &certificate.into_inner(), true)?)))
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
                format!("deactivate_cert: Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.inactive = true;

            Ok(ca.db().cert_update(&cert).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("deactivate_cert: Error updating Cert '{:?}'", e),
                )
            })?)
        } else {
            Err(ReturnError::new(
                ReturnStatus::NotFound,
                format!("deactivate_cert: Fingerprint '{}' not found", fp),
            )
            .into())
        }
    })
}

/// Mark a cert as "delisted" in the OpenPGP CA database.
/// As a result, the cert will not be exported to WKD anymore.
///
/// Note: existing CA certifications will still get renewed for delisted
/// certs, but as the cert is not published via WKD, third parties might not
/// learn about refreshed certifications.
///
/// CAUTION:
/// This method is probably rarely appropriate. In most cases, it's better
/// to "deactivate" a cert (in almost all cases, it is best to continually
/// serve the latest version of a cert to third parties, so they can learn
/// about e.g. revocations on the cert)
#[delete("/certs/<fp>")]
fn delist_cert(fp: String) -> Result<(), BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let cert = ca.cert_get_by_fingerprint(&fp).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("delist_cert: Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.delisted = true;

            ca.db().cert_update(&cert).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("delist_cert: Error updating Cert '{:?}'", e),
                )
            })?;
        } else {
            return Err(ReturnError::new(
                ReturnStatus::NotFound,
                format!("delist_cert: Fingerprint '{}' not found", fp),
            )
            .into());
        }

        Ok(())
    })
}

/// Refresh CA certifications on all user certs.
///
/// For certifications which are going to expire soon:
/// Make a new certification, unless the user cert is marked as "deactivated".
#[post("/refresh_ca_certifications")]
fn refresh_certifications() -> Result<(), BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        Ok(ca
            .certs_refresh_ca_certifications(30, CERTIFICATION_DAYS)
            .map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("Error during certs_refresh_ca_certifications '{:?}'", e),
                )
            })?)
    })
}

/// Poll for updates to user keys (e.g. on https://keys.openpgp.org/)
#[post("/poll_updates")]
fn poll_for_updates() -> String {
    unimplemented!()
}

/// Check for certs that will expire within "days" days.
#[get("/certs/expire/<days>")]
fn check_expiring(days: u64) -> Result<Json<Vec<CertInfo>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let expired = ca.certs_expired(days).map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!("check_expiring: Error looking up expired certs '{:?}'", e),
            )
        })?;

        let mut res = vec![];

        for cert in expired.keys() {
            let cert = pgp::to_cert(cert.pub_cert.as_bytes()).map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!("check_expiring: Error in armored_to_cert '{:?}'", e),
                )
            })?;

            let ci = (&cert).try_into().map_err(|e| {
                ReturnError::new(
                    ReturnStatus::InternalError,
                    format!(
                        "check_expiring: Error getting cert_info for cert \
                        '{:?}'",
                        e
                    ),
                )
            })?;

            res.push(ci);
        }

        Ok(Json(res))
    })
}

/// Ping, good for checking the service is alive
#[get("/ping")]
fn ping() -> Status {
    Status::Ok
}

/// Healthz, ensure the service can connect to its dependencies and is ready
/// to take traffic.
/// Tests for DB availability and that the CA has been initialized.
#[get("/healthz")]
fn healthz() -> Status {
    if CA.with(|ca| ca.ca_get_cert_pub()).is_err() {
        // failed to load the CA Cert from the database
        Status::InternalServerError
    } else {
        Status::Ok
    }
}

pub fn run(db: Option<String>) -> rocket::Rocket<Build> {
    DB.set(db).unwrap();

    rocket::build().mount(
        "/",
        routes![
            certs_by_email,
            cert_by_fp,
            check_certs,
            post_certs,
            deactivate_cert,
            delist_cert,
            refresh_certifications,
            poll_for_updates,
            check_expiring,
            ping,
            healthz,
        ],
    )
}
