// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! REST Interface for OpenPGP CA.
//! This is an experimental API for use at FSFE.

use std::collections::HashSet;
use std::ops::Deref;

use once_cell::sync::OnceCell;
use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;

use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{HashAlgorithm, RevocationStatus};
use sequoia_openpgp::Cert;

use oca_json::*;

use super::ca::OpenpgpCa;
use super::models;
use crate::restd::certinfo::CertInfo;

pub mod certinfo;
mod cli;
pub mod client;
pub mod oca_json;
mod util;

static DB: OnceCell<Option<String>> = OnceCell::new();

const POLICY: &StandardPolicy = &StandardPolicy::new();

// FIXME
const POLICY_BAD_URL: &str = "https://very-bad-cert.example.org";
const POLICY_SHA1_BAD_URL: &str = "https://bad-cert-with-sha1.example.org";

thread_local! {
    static CA: OpenpgpCa = OpenpgpCa::new(DB.get().unwrap().as_deref())
        .expect("OpenPGP CA new() failed - database problem?");
}

// key size limit (armored): 1 mbyte
const KEY_SIZE_LIMIT: usize = 1024 * 1024;

// CA certifications are good for 365 days
const CERTIFICATION_DAYS: Option<u64> = Some(365);

fn cert_policy_check(cert: &Cert) -> Result<(), ReturnError> {
    // check if cert is valid according to sequoia standard policy
    let valid_sp = cert.with_policy(POLICY, None);

    // check if cert is valid according to "sequoia standard policy plus sha1"
    let mut sp_plus_sha1 = StandardPolicy::new();
    sp_plus_sha1.accept_hash(HashAlgorithm::SHA1);
    let valid_sp_plus_sha1 = cert.with_policy(&sp_plus_sha1, None);

    // derive a judgment about the cert from the two policy checks
    match (&valid_sp, &valid_sp_plus_sha1) {
        (Ok(_), Ok(_)) => (Ok(())), // cert is good, according to policy
        (Err(_), Err(e_allowing_sha1)) => {
            // Cert is considered bad, even allowing for SHA1

            Err(ReturnError::new_with_url(
                ReturnStatus::CertUnusable,
                POLICY_BAD_URL.to_string(),
                format!(
                    "Cert invalid according to standard policy: '{:?}'",
                    e_allowing_sha1
                ),
            ))
        }

        (Err(e), Ok(_)) => {
            // SHA1 hashes are used, otherwise the standard policy has no
            // objections to this cert (so this cert could be repaired)

            Err(ReturnError::new_with_url(
                ReturnStatus::CertFixable,
                POLICY_SHA1_BAD_URL.to_string(),
                format!("Cert invalid because it uses SHA1 hashes: '{:?}'", e),
            ))
        }

        (Ok(_), Err(e)) => {
            // standard policy is happy, but relaxing by sha1 shows error
            // -> this should never happen!

            Err(ReturnError::new(
                ReturnStatus::InternalError,
                format!("Unexpected Cert check result: '{:?}'", e),
            ))
        }
    }
}

fn validate_and_normalize_user_ids(
    cert: &Cert,
    my_domain: &str,
    user_emails: &[String],
) -> Result<Cert, ReturnError> {
    // validate user_emails vs. the user ids in cert

    // emails from the cert's user_ids
    let cert_uid_emails: HashSet<_> = cert
        .userids()
        .flat_map(|uid| uid.email().ok())
        .flatten()
        .collect();

    // the intersection between "user_emails" and "cert_uid_emails" must
    // be non-empty
    if cert_uid_emails
        .intersection(&user_emails.iter().cloned().collect::<HashSet<_>>())
        .next()
        .is_none()
    {
        return Err(ReturnError::new(
            ReturnStatus::CertMissingLocalUserId,
            format!(
                "Cert does not contain user_ids for any of '{:?}'",
                user_emails
            ),
        ));
    }

    // split up user_ids between "external" and "internal" emails, then:
    match util::split_emails(&my_domain, user_emails) {
        Ok((int_provided, _)) => {
            let mut int_remaining: HashSet<_> = int_provided.iter().collect();
            let mut filter_uid = Vec::new();

            for user_id in cert.userids() {
                if let Ok(Some(email)) = user_id.email() {
                    let in_domain = util::is_email_in_domain(
                        &email, &my_domain,
                    )
                    .map_err(|_e| {
                        // FIXME?
                        ReturnError::new(
                            ReturnStatus::BadEmail,
                            format!("Bad email in User ID '{:?}'", user_id),
                        )
                    })?;

                    if in_domain {
                        // FIXME
                        // handle emails that are used in multiple User IDs

                        // a) all provided internal "email" entries must exist in cert user_ids
                        if int_remaining.contains(&email) {
                            int_remaining.remove(&email);
                        } else {
                            // b) flag additional "internal" emails for removal
                            filter_uid.push(user_id.userid());
                        }
                    }
                } else {
                    // Filter out User IDs with bad emails
                    filter_uid.push(user_id.userid());
                }
            }

            // b) strip additional "internal"s user_ids from the Cert
            let mut normalize = cert.clone();
            for filter in filter_uid {
                normalize = util::user_id_filter(normalize, &filter)
            }

            if !int_remaining.is_empty() {
                // some provided internal "email" entries do not exist in user_ids
                // -> not ok!

                return Err(ReturnError::new(
                    ReturnStatus::CertMissingLocalUserId,
                    format!(
                        "User certificate does not contain user_ids for '{:?}'",
                        int_remaining
                    ),
                ));
            }

            Ok(normalize)
        }
        Err(e) => Err(ReturnError::new(
            ReturnStatus::BadEmail,
            format!("Error with provided email addresses {:?}", e),
        )),
    }
}

fn check_and_normalize_cert(
    cert: &Cert,
    my_domain: &str,
    user_emails: &[String],
) -> Result<(Cert, CertInfo), ReturnBadJSON> {
    let ci = CertInfo::from_cert(cert).map_err(|e| {
        ReturnBadJSON::new(
            ReturnError::new(
                ReturnStatus::InternalError,
                format!["CertInfo::from_cert() failed {:?}", e],
            ),
            None,
        )
    })?;

    // private keys are illegal
    if cert.is_tsk() {
        return Err(ReturnBadJSON::new(
            ReturnError::new(
                ReturnStatus::PrivateKey,
                String::from("The user provided private key material"),
            ),
            Some(ci),
        ));
    }

    // reject unreasonably big keys
    if let Ok(armored) = OpenpgpCa::cert_to_armored(cert) {
        let len = armored.len();
        if len > KEY_SIZE_LIMIT {
            return Err(ReturnBadJSON::new(
                ReturnError::new(
                    ReturnStatus::CertSizeLimit,
                    format!("User cert is too big ({} bytes)", len),
                ),
                Some(ci),
            ));
        }
    } else {
        return Err(ReturnBadJSON::new(
            ReturnError::new(
                ReturnStatus::InternalError,
                "Failed to re-armor cert",
            ),
            Some(ci),
        ));
    }

    // perform policy checks
    // (and distinguish/notify fixable vs unfixable problems with cert)
    if let Err(re) = cert_policy_check(cert) {
        return Err(ReturnBadJSON::new(re, Some(ci)));
    }

    // check and normalize user_ids
    let norm = validate_and_normalize_user_ids(cert, my_domain, user_emails)
        .map_err(|re| ReturnBadJSON::new(re, Some(ci.clone())))?;

    Ok((norm, ci))
}

fn check_and_normalize_certs(
    ca: &OpenpgpCa,
    certificate: &Certificate,
) -> std::result::Result<Vec<CertResultJSON>, ReturnError> {
    let certs = OpenpgpCa::armored_keyring_to_certs(&certificate.cert)
        .map_err(|e| {
            ReturnError::new(
                ReturnStatus::InternalError,
                format!(
                    "Error parsing the user-provided OpenPGP keyring:\n{:?}",
                    e
                ),
            )
        })?;

    // get the domain of this CA
    let my_domain = ca.get_ca_domain().map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("Error while getting the CA's domain {:?}", e),
        )
    })?;

    // collects results for each cert
    let mut results = vec![];

    for cert in certs {
        match check_and_normalize_cert(&cert, &my_domain, &certificate.email) {
            Ok((norm, cert_info)) => {
                let mut c = certificate.clone();

                let armored = OpenpgpCa::cert_to_armored(&norm);
                if let Ok(armored) = armored {
                    c.cert = armored;

                    let rj = ReturnGoodJSON {
                        certificate: c,
                        action: None,
                        cert_info,
                    };

                    results.push(CertResultJSON::Good(rj));
                } else {
                    // this should probably never happen?
                    let rj = ReturnBadJSON {
                        error: ReturnError::new(
                            ReturnStatus::InternalError,
                            "Couldn't re-armor cert",
                        ),
                        cert_info: Some(cert_info),
                    };

                    results.push(CertResultJSON::Bad(rj));
                }
            }
            Err(err) => {
                results.push(CertResultJSON::Bad(err));
            }
        }
    }

    Ok(results)
}

fn load_certificate_data(
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

fn cert_to_cert_info(
    cert: &Cert,
) -> Result<CertInfo, BadRequest<Json<ReturnError>>> {
    CertInfo::from_cert(cert).map_err(|e| {
        ReturnError::bad_req(
            ReturnStatus::InternalError,
            format!("Error in CertInfo::from_cert() '{:?}'", e),
        )
    })
}

#[get("/certs/by_email/<email>")]
fn certs_by_email(
    email: String,
) -> Result<Json<Vec<ReturnGoodJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let mut res = Vec::new();

        let certs = ca.certs_get(&email).map_err(|e| {
            ReturnError::bad_req(
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
                    ReturnError::bad_req(
                        ReturnStatus::InternalError,
                        format!(
                            "certs_by_email: error during armored_to_cert \
                            '{:?}'",
                            e
                        ),
                    )
                })?;

            let cert_info = cert_to_cert_info(&cert)?;

            let certificate = load_certificate_data(&ca, &c)
                .map_err(|e| BadRequest(Some(Json(e))))?;

            let r = ReturnGoodJSON {
                cert_info,
                action: None,
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
            ReturnError::bad_req(
                ReturnStatus::InternalError,
                format!(
                    "certs_by_fp: error loading certificate data \
                '{:?}'",
                    e
                ),
            )
        })?;

        if let Some(c) = c {
            let cert =
                OpenpgpCa::armored_to_cert(&c.pub_cert).map_err(|e| {
                    ReturnError::bad_req(
                        ReturnStatus::InternalError,
                        format!(
                            "certs_by_fp: error during armored_to_cert \
                            '{:?}'",
                            e
                        ),
                    )
                })?;

            let certificate = load_certificate_data(&ca, &c)
                .map_err(|e| BadRequest(Some(Json(e))))?;

            let cert_info = cert_to_cert_info(&cert)?;

            Ok(Json(Some(ReturnGoodJSON {
                cert_info,
                certificate,
                action: None,
            })))
        } else {
            Ok(Json(None))
        }
    })
}

fn fp_exists(fp: &str, ca: &OpenpgpCa) -> Result<bool, anyhow::Error> {
    let c = ca.cert_get_by_fingerprint(&fp)?;
    if c.is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Similar to "post_user", but doesn't commit data to DB.
///
/// Returns information about what the commit would result in.
#[get("/certs/check", data = "<certificate>", format = "json")]
fn check_certs(
    certificate: Json<Certificate>,
) -> Result<Json<Vec<CertResultJSON>>, BadRequest<Json<ReturnError>>> {
    CA.with(|ca| {
        let certificate = certificate.into_inner();
        let checked = check_and_normalize_certs(&ca, &certificate);

        // FIXME: do more linting?

        let mut res = vec![];

        match checked {
            Ok(crjs) => {
                // check if fingerprint exists in db
                // -> action "new" or "update"

                for crj in crjs {
                    match crj {
                        CertResultJSON::Good(mut rj) => {
                            let cert_new = OpenpgpCa::armored_to_cert(
                                &rj.certificate.cert,
                            );
                            if cert_new.is_err() {
                                let error = ReturnError::new(
                                    ReturnStatus::InternalError,
                                    format!(
                                        "Error in armored_to_cert(): {:?}",
                                        cert_new.err()
                                    ),
                                );
                                let cert_info = Some(rj.cert_info);
                                let rbj = ReturnBadJSON { error, cert_info };
                                res.push(CertResultJSON::Bad(rbj));
                                continue;
                            }

                            let cert_new = cert_new.unwrap();

                            let revoked =
                                matches!(cert_new.revocation_status(POLICY, None),
                                   RevocationStatus::Revoked(_));

                            if revoked {
                                rj.action = Some(Action::Revoked);
                            } else {
                                let exists = fp_exists(&rj.cert_info
                                    .primary.fingerprint, &ca);
                                if exists.is_err() {
                                    let error = ReturnError::new(
                                        ReturnStatus::InternalError,
                                        format!(
                                            "Error during database lookup by fingerprint: {:?}",
                                            exists.err()
                                        ),
                                    );
                                    let cert_info = Some(rj.cert_info);
                                    let rbj = ReturnBadJSON { error, cert_info };
                                    res.push(CertResultJSON::Bad(rbj));
                                    continue;
                                }
                                if exists.unwrap() {
                                    rj.action = Some(Action::Merge);
                                } else {
                                    rj.action = Some(Action::New);
                                }
                            }

                            res.push(CertResultJSON::Good(rj));
                        }
                        CertResultJSON::Bad(re) => {
                            res.push(CertResultJSON::Bad(re));
                        }
                    }
                }
            }
            Err(err) => {
                // We can't return information for individual Certs
                // -> return one general error
                return Err(BadRequest(Some(Json(err))));
            }
        }

        Ok(Json(res))
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
        let cert = certificate.into_inner();

        let mut res = vec![];

        // check and normalize user-provided public key
        let crjs = check_and_normalize_certs(ca, &cert)
            .map_err(|e| BadRequest(Some(Json(e))))?;

        for crj in crjs {
            match crj {
                CertResultJSON::Good(rj) => {

                    // check if a cert with this fingerprint exists already
                    let fp = rj.cert_info.primary.fingerprint.clone();

                    let cert_by_fp = ca.cert_get_by_fingerprint(&fp);
                    if cert_by_fp.is_err() {
                        let error = ReturnError::new(
                            ReturnStatus::InternalError,
                            format!(
                                "Error during database lookup by fingerprint: {:?}",
                                cert_by_fp.err()
                            ),
                        );
                        let cert_info = Some(rj.cert_info);
                        let rbj = ReturnBadJSON { error, cert_info };
                        res.push(CertResultJSON::Bad(rbj));
                        continue;
                    }
                    let cert_by_fp = cert_by_fp.unwrap();

                    let cert_normalized =
                        OpenpgpCa::armored_to_cert(&rj.certificate.cert);
                    if cert_normalized.is_err() {
                        let error = ReturnError::new(
                            ReturnStatus::InternalError,
                            format!(
                                "Error unarmoring the normalized cert: {:?}",
                                cert_normalized.err()
                            ),
                        );
                        let cert_info = Some(rj.cert_info);
                        let rbj = ReturnBadJSON { error, cert_info };
                        res.push(CertResultJSON::Bad(rbj));
                        continue;
                    }
                    let cert_normalized = cert_normalized.unwrap();

                    if let Some(cert_by_fp) = cert_by_fp {
                        // fingerprint of the key already exists
                        //   -> merge data, update existing key
                        let existing = OpenpgpCa::armored_to_cert(
                            &cert_by_fp.pub_cert,
                        );

                        if existing.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                format!(
                                    "Error while deserializing armored Cert: {}",
                                    &cert_by_fp.pub_cert,
                                ),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }

                        let existing = existing.unwrap();

                        let updated =
                            existing.merge_public(cert_normalized);
                        if updated.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                String::from("Error while merging Certs"),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }
                        let updated = updated.unwrap();

                        let armored =
                            OpenpgpCa::cert_to_armored(&updated);
                        if armored.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                String::from(
                                    "Error while serializing merged Cert",
                                ),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }
                        let armored = armored.unwrap();

                        let r = ca.cert_import_update(&armored);
                        if r.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                format!("Error updating Cert in database: {:?}", r.err()),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }
                    } else {
                        // fingerprint doesn't exist yet -> new cert

                        let armored = OpenpgpCa::cert_to_armored(&cert_normalized);
                        if armored.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                String::from("Error while serializing new Cert"),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }
                        let armored = armored.unwrap();

                        let r = ca.cert_import_new(
                            &armored,
                            vec![],
                            cert.name.as_deref(),
                            cert.email
                                .iter()
                                .map(|e| e.deref())
                                .collect::<Vec<_>>()
                                .as_slice(),
                            CERTIFICATION_DAYS,
                        );
                        if r.is_err() {
                            let error = ReturnError::new(
                                ReturnStatus::InternalError,
                                format!("Error importing Cert into database: {:?}", r.err()),
                            );
                            let cert_info = Some(rj.cert_info);
                            let rbj = ReturnBadJSON { error, cert_info };
                            res.push(CertResultJSON::Bad(rbj));
                            continue;
                        }
                    }
                }
                CertResultJSON::Bad(_) => {
                    res.push(crj)
                }
            }
        }

        Ok(Json(res))
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
            ReturnError::bad_req(
                ReturnStatus::InternalError,
                format!("Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.inactive = true;

            ca.cert_update(&cert).map_err(|e| {
                ReturnError::bad_req(
                    ReturnStatus::InternalError,
                    format!("Error updating Cert '{:?}'", e),
                )
            })?;
        } else {
            return Err(ReturnError::bad_req(
                ReturnStatus::NotFound,
                format!("Fingerprint '{}' not found", fp),
            ));
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
            ReturnError::bad_req(
                ReturnStatus::InternalError,
                format!("Error looking up Fingerprint '{:?}'", e),
            )
        })?;

        if let Some(mut cert) = cert {
            cert.delisted = true;

            ca.cert_update(&cert).map_err(|e| {
                ReturnError::bad_req(
                    ReturnStatus::InternalError,
                    format!("Error updating Cert '{:?}'", e),
                )
            })?;
        } else {
            return Err(ReturnError::bad_req(
                ReturnStatus::NotFound,
                format!("Fingerprint '{}' not found", fp),
            ));
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
        ca.certs_refresh_ca_certifications(30, 365).map_err(|e| {
            ReturnError::bad_req(
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
