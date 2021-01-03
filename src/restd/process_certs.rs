// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{HashAlgorithm, RevocationStatus};
use sequoia_openpgp::Cert;

use crate::ca::OpenpgpCa;
use crate::restd::cert_info::CertInfo;
use crate::restd::json::*;
use crate::restd::{
    util, CERTIFICATION_DAYS, CERT_SIZE_LIMIT, POLICY_BAD_URL,
    POLICY_SHA1_BAD_URL,
};

use std::collections::HashSet;
use std::ops::Deref;

const POLICY: &StandardPolicy = &StandardPolicy::new();

pub fn cert_to_cert_info(cert: &Cert) -> Result<CertInfo, ReturnError> {
    CertInfo::from_cert(cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("Error in CertInfo::from_cert() '{:?}'", e),
        )
    })
}

fn cert_policy_check(cert: &Cert) -> Result<(), CertError> {
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

            Err(CertError::new_with_url(
                CertStatus::CertUnusable,
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

            Err(CertError::new_with_url(
                CertStatus::CertFixable,
                POLICY_SHA1_BAD_URL.to_string(),
                format!("Cert invalid because it uses SHA1 hashes: '{:?}'", e),
            ))
        }

        (Ok(_), Err(e)) => {
            // standard policy is happy, but relaxing by sha1 shows error
            // -> this should never happen!

            Err(CertError::new(
                CertStatus::InternalError,
                format!("Unexpected Cert check result: '{:?}'", e),
            ))
        }
    }
}

fn validate_and_normalize_user_ids(
    cert: &Cert,
    my_domain: &str,
    user_emails: &[String],
) -> Result<Cert, CertError> {
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
        return Err(CertError::new(
            CertStatus::CertMissingLocalUserId,
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
                        CertError::new(
                            CertStatus::BadEmail,
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

                return Err(CertError::new(
                    CertStatus::CertMissingLocalUserId,
                    format!(
                        "User certificate does not contain user_ids for '{:?}'",
                        int_remaining
                    ),
                ));
            }

            Ok(normalize)
        }
        Err(e) => Err(CertError::new(
            CertStatus::BadEmail,
            format!("Error with provided email addresses {:?}", e),
        )),
    }
}

fn check_cert(cert: &Cert) -> Result<CertInfo, ReturnBadJSON> {
    let ci = CertInfo::from_cert(cert).map_err(|e| {
        ReturnBadJSON::new(
            CertError::new(
                CertStatus::InternalError,
                format!["CertInfo::from_cert() failed {:?}", e],
            ),
            None,
        )
    })?;

    // private keys are illegal
    if cert.is_tsk() {
        return Err(ReturnBadJSON::new(
            CertError::new(
                CertStatus::PrivateKey,
                String::from("The user provided private key material"),
            ),
            Some(ci),
        ));
    }

    // reject unreasonably big keys
    if let Ok(armored) = OpenpgpCa::cert_to_armored(cert) {
        let len = armored.len();
        if len > CERT_SIZE_LIMIT {
            return Err(ReturnBadJSON::new(
                CertError::new(
                    CertStatus::CertSizeLimit,
                    format!("User cert is too big ({} bytes)", len),
                ),
                Some(ci),
            ));
        }
    } else {
        return Err(ReturnBadJSON::new(
            CertError::new(
                CertStatus::InternalError,
                "Failed to re-armor cert",
            ),
            Some(ci),
        ));
    }

    Ok(ci)
}

fn policy_check_and_uid_normalize(
    cert: &Cert,
    my_domain: &str,
    user_emails: &[String],
) -> Result<Cert, CertError> {
    // perform policy checks
    // (and distinguish/notify fixable vs unfixable problems with cert)
    cert_policy_check(cert)?;

    // check and normalize user_ids
    validate_and_normalize_user_ids(cert, my_domain, user_emails)
}

fn process_cert(
    cert: &Cert,
    my_domain: &str,
    certificate: &Certificate,
    ca: &OpenpgpCa,
    persist: bool,
) -> Result<ReturnGoodJSON, ReturnBadJSON> {
    let cert_info = check_cert(&cert)?;

    // check if a cert with this fingerprint exists already in db
    // (new vs update)
    let fp = &cert_info.primary.fingerprint;

    let cert_in_ca_db = ca.cert_get_by_fingerprint(fp).map_err(|e| {
        let ce = CertError::new(
            CertStatus::InternalError,
            format!("Error during database lookup by fingerprint: {:?}", e),
        );
        ReturnBadJSON::new(ce, Some(cert_info.clone()))
    })?;

    let is_update = cert_in_ca_db.is_some();

    // merge new cert with existing cert, if any
    let merged = match cert_in_ca_db {
        None => cert.clone(),
        Some(c) => {
            let db_cert =
                OpenpgpCa::armored_to_cert(&c.pub_cert).map_err(|e| {
                    let error = CertError::new(
                        CertStatus::InternalError,
                        format!("Error unarmoring cert from CA DB: {:?}", e),
                    );

                    ReturnBadJSON::new(error, Some(cert_info.clone()))
                })?;

            db_cert.merge_public(cert.clone()).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!("Error merging new cert with DB cert: {:?}", e),
                );

                ReturnBadJSON::new(error, Some(cert_info.clone()))
            })?
        }
    };

    // check if the cert is revoked
    let is_revoked = matches!(
        merged.revocation_status(POLICY, None),
        RevocationStatus::Revoked(_)
    );

    // policy checks, normalization and further processing
    match policy_check_and_uid_normalize(
        &merged,
        &my_domain,
        &certificate.email,
    ) {
        Ok(norm) => {
            let cert_info_norm = CertInfo::from_cert(&norm).map_err(|e| {
                ReturnBadJSON::new(
                    CertError::new(
                        CertStatus::InternalError,
                        format![
                            "CertInfo::from_cert() failed for 'norm' {:?}",
                            e
                        ],
                    ),
                    None,
                )
            })?;

            let armored = OpenpgpCa::cert_to_armored(&norm);
            if let Ok(armored) = armored {
                let mut certificate = certificate.clone();

                certificate.cert = armored;

                let action;
                let upload;

                if persist {
                    // "post" run
                    upload = None; // don't recommend action after persisting

                    let cert_info = Some(cert_info_norm.clone());

                    if is_update {
                        // update cert in db
                        action = Some(Action::Update);

                        ca.cert_import_update(&certificate.cert)
                            .map_err(|e|
                                {
                                    let error = CertError::new(
                                        CertStatus::InternalError,
                                        format!(
                                            "Error updating Cert in database: {:?}",
                                            e
                                        ),
                                    );

                                    ReturnBadJSON::new(
                                        error,
                                        cert_info,
                                    )
                                }
                            )?;
                    } else {
                        // add new cert to db
                        action = Some(Action::New);

                        let key = &certificate.cert;
                        let name = certificate.name.as_deref();
                        let emails = certificate
                            .email
                            .iter()
                            .map(|e| e.deref())
                            .collect::<Vec<_>>();

                        ca.cert_import_new(
                            key,
                            vec![],
                            name,
                            emails.as_slice(),
                            Some(CERTIFICATION_DAYS),
                        )
                        .map_err(|e| {
                            let error = CertError::new(
                                CertStatus::InternalError,
                                format!(
                                    "Error importing Cert into database: {:?}",
                                    e
                                ),
                            );
                            ReturnBadJSON::new(error, cert_info)
                        })?;
                    }
                } else {
                    // "check" run
                    if is_update {
                        action = Some(Action::Update);
                        upload = Some(Upload::Recommended);
                    } else {
                        action = Some(Action::New);
                        if is_revoked {
                            upload = Some(Upload::Recommended);
                        } else {
                            upload = Some(Upload::Possible);
                        }
                    }
                }

                Ok(ReturnGoodJSON {
                    certificate,
                    action,
                    upload,
                    cert_info: cert_info_norm,
                })
            } else {
                // this should probably never happen?
                Err(ReturnBadJSON::new(
                    CertError::new(
                        CertStatus::InternalError,
                        "Couldn't re-armor cert",
                    ),
                    Some(cert_info),
                ))
            }
        }
        Err(err) => Err(ReturnBadJSON::new(err, Some(cert_info))),
    }
}

pub fn process_certs(
    ca: &OpenpgpCa,
    certificate: &Certificate,
    persist: bool,
) -> Result<Vec<CertResultJSON>, ReturnError> {
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

    // iterate over certs and collect results for each cert
    Ok(certs
        .iter()
        .map(|cert| {
            process_cert(&cert, &my_domain, &certificate, ca, persist).into()
        })
        .collect())
}
