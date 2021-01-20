// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::time::Duration;
use std::collections::HashSet;
use std::ops::Deref;
use std::time::SystemTime;

use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{HashAlgorithm, RevocationStatus};
use sequoia_openpgp::Cert;

use crate::ca::OpenpgpCa;
use crate::restd;
use crate::restd::cert_info::CertInfo;
use crate::restd::json::*;
use crate::restd::util::{is_email_in_domain, split_emails, user_id_filter};

const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();

/// Warnings for this cert.
///
/// Warnings are currently generated for:
/// - Standard Policy gives an error for 'now + 2 years'
/// - Cert is not alive() in 'now + 3 months'
///
/// Assumption: the cert has been checked and found good by the
/// StandardPolicy for `now`.
pub fn cert_to_warn(cert: &Cert) -> Result<Option<Vec<Warning>>, CertError> {
    let mut warns = Vec::new();
    let now = SystemTime::now();

    // Check if StandardPolicy is bad in 'now + 2 years', but good when
    // allowing for SHA1.
    let now2y = now
        .clone()
        .checked_add(Duration::from_secs(60 * 60 * 24 * 365 * 2))
        .ok_or(CertError::new(
            CertStatus::InternalError,
            "cert_to_warn: duration checked_add failed",
        ))?;

    let policy_plus2y = StandardPolicy::at(now2y);

    let valid2y = cert.with_policy(&policy_plus2y, Some(now2y));

    let mut sp_plus_sha1 = StandardPolicy::at(now2y);
    sp_plus_sha1.accept_hash(HashAlgorithm::SHA1);
    let valid2y_sha1 = cert.with_policy(&sp_plus_sha1, now2y);

    if valid2y.is_err() && valid2y_sha1.is_ok() {
        warns.push(Warning::new(
            WarnStatus::WeakCryptoSHA1,
            "This certificate relies on SHA1 hashes, which are deprecated. It should be updated!",
        ));
    }

    // Check if cert is alive() now, but will not be in 'now + 3 months'.
    // If so: warn about imminent expiry.

    let now3m = now
        .clone()
        .checked_add(Duration::from_secs(60 * 60 * 24 * 30 * 3))
        .ok_or(CertError::new(
            CertStatus::InternalError,
            "cert_to_warn: duration checked_add failed",
        ))?;

    let policy_plus3m = StandardPolicy::at(now3m);

    let valid_cert_now = cert.with_policy(STANDARD_POLICY, None);

    let valid_cert_3m = cert.with_policy(&policy_plus3m, Some(now3m));

    if valid_cert_now.is_ok()
        && valid_cert_now.unwrap().alive().is_ok()
        && valid_cert_3m.is_ok()
        && valid_cert_3m.unwrap().alive().is_err()
    {
        warns.push(Warning::new(
            WarnStatus::ExpiresSoon,
            "Will expire in the next 90 days",
        ));
    }

    if warns.is_empty() {
        Ok(None)
    } else {
        Ok(Some(warns))
    }
}

pub fn cert_to_cert_info(cert: &Cert) -> Result<CertInfo, ReturnError> {
    CertInfo::from_cert(cert).map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("Error in CertInfo::from_cert() '{:?}'", e),
        )
    })
}

fn cert_policy_check(cert: &Cert) -> Result<ValidCert, CertError> {
    // check if cert is valid according to sequoia standard policy
    cert.with_policy(STANDARD_POLICY, None).map_err(|e| {
        CertError::new_with_url(
            CertStatus::BadCert,
            // restd::POLICY_BAD_URL.to_string(),
            None,
            format!("Cert invalid according to standard policy: '{:?}'", e),
        )
    })
}

// 'my_domain' is the domain that this CA is used over (like 'example.org').
//
// 'user_emails' is a list of email addresses that the client considers to
// be correctly used by this user (typically this will be local emails, such
// as ('alice@example.org').
//
// remove all user_ids with emails in "my_domain" that aren't contained in
// 'user_emails'
fn validate_and_strip_user_ids(
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
                "Cert does not contain user_ids matching '{:?}'",
                user_emails
            ),
        ));
    }

    // split up user_ids between "external" and "internal" emails, then:
    match split_emails(&my_domain, user_emails) {
        Ok((int_provided, _)) => {
            let mut filter_uid = Vec::new();

            for user_id in cert.userids() {
                if let Ok(Some(email)) = user_id.email() {
                    let in_domain = is_email_in_domain(&email, &my_domain);

                    if in_domain.is_ok() && in_domain.unwrap() {
                        // this is a User ID with an email in the domain
                        // "my_domain"

                        if !int_provided.contains(&email) {
                            // flag unexpected "internal" emails for removal
                            filter_uid.push(user_id.userid());
                        }
                    }
                }
            }

            // strip unexpected "internal" user_ids from the Cert
            let mut stripped = cert.clone();
            for filter in filter_uid {
                stripped = user_id_filter(stripped, &filter)
            }

            Ok(stripped)
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
                format!["check_cert: CertInfo::from_cert() failed {:?}", e],
            ),
            None,
        )
    })?;

    // private keys are illegal
    if cert.is_tsk() {
        return Err(ReturnBadJSON::new(
            CertError::new(
                CertStatus::PrivateKey,
                String::from(
                    "check_cert: The user provided private key material",
                ),
            ),
            Some(ci),
        ));
    }

    // reject unreasonably big certificates
    if let Ok(armored) = OpenpgpCa::cert_to_armored(cert) {
        let len = armored.len();
        if len > restd::CERT_SIZE_LIMIT {
            return Err(ReturnBadJSON::new(
                CertError::new(
                    CertStatus::CertSizeLimit,
                    format!(
                        "check_cert: User cert is too big ({} bytes)",
                        len
                    ),
                ),
                Some(ci),
            ));
        }
    } else {
        return Err(ReturnBadJSON::new(
            CertError::new(
                CertStatus::InternalError,
                "check_cert: Failed to re-armor cert",
            ),
            Some(ci),
        ));
    }

    Ok(ci)
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
            format!(
                "process_cert: Error during db lookup by fingerprint: {:?}",
                e
            ),
        );
        ReturnBadJSON::new(ce, Some(cert_info.clone()))
    })?;

    // will this cert be processed as an update to an existing version of it?
    let is_update = cert_in_ca_db.is_some();

    if is_update {
        // input sanity check: delisted/inactive may not be changed by
        // input parameter, for now

        if (certificate.delisted.is_some()
            && certificate.delisted
                != Some(cert_in_ca_db.as_ref().unwrap().delisted))
            || (certificate.inactive.is_some()
                && certificate.inactive
                    != Some(cert_in_ca_db.as_ref().unwrap().inactive))
        {
            let ce = CertError::new(
                CertStatus::InternalError,
                format!(
                    "process_cert: changing delisted and inactive is \
                    not currently allowed via this call {:?}",
                    certificate
                ),
            );
            return Err(ReturnBadJSON::new(ce, Some(cert_info.clone())));
        }
    }

    // merge new cert with existing cert, if any
    let merged = match cert_in_ca_db {
        None => cert.clone(),
        Some(ref c) => {
            let db_cert =
                OpenpgpCa::armored_to_cert(&c.pub_cert).map_err(|e| {
                    let error = CertError::new(
                        CertStatus::InternalError,
                        format!(
                            "process_cert: Error un-armoring cert from CA DB: {:?}",
                            e
                        ),
                    );

                    ReturnBadJSON::new(error, Some(cert_info.clone()))
                })?;

            db_cert.merge_public(cert.clone()).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!(
                        "process_cert: Error merging new cert with DB \
                        cert: {:?}",
                        e
                    ),
                );

                ReturnBadJSON::new(error, Some(cert_info.clone()))
            })?
        }
    };
    let _ = cert; // drop previous version of the cert

    // perform policy checks
    let valid_cert = cert_policy_check(&merged)
        .map_err(|ce| ReturnBadJSON::new(ce, Some(cert_info.clone())))?;
    let _ = merged; // drop previous version of the cert

    // check if the cert is revoked
    let is_revoked =
        matches!(valid_cert.revocation_status(), RevocationStatus::Revoked(_));

    // check and normalize user_ids
    let norm = validate_and_strip_user_ids(
        &valid_cert,
        &my_domain,
        &certificate.email,
    )
    .map_err(|e| ReturnBadJSON::new(e, Some(cert_info.clone())))?;

    let cert_info_norm = CertInfo::from_cert(&norm)
        .map_err(|e| {
            CertError::new(
                CertStatus::InternalError,
                format!(
                    "process_cert: CertInfo::from_cert() failed for 'norm' {:?}",
                    e
                ),
            )
        })
        .map_err(|ce| ReturnBadJSON::new(ce, None))?;

    let armored = OpenpgpCa::cert_to_armored(&norm).map_err(|e|
        // this should probably never happen?
        ReturnBadJSON::new(
            CertError::new(
                CertStatus::InternalError,
                format!("process_cert: Couldn't re-armor cert {:?}", e),
            ),
            Some(cert_info.clone()),
        ))?;

    let action;
    let upload;

    if persist {
        // "post" run
        upload = None; // don't recommend action after persisting

        let cert_info = Some(cert_info_norm.clone());

        if is_update {
            // update cert in db
            action = Some(Action::Update);

            // FIXME: how/when should changes to name/email be persisted?

            ca.cert_import_update(&armored).map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!(
                        "process_cert: Error updating Cert in database: {:?}",
                        e
                    ),
                );

                ReturnBadJSON::new(error, cert_info.clone())
            })?;

            for rev in &certificate.revocations {
                ca.revocation_add(rev).map_err(|e| {
                    let ce = CertError::new(
                        CertStatus::InternalError,
                        format!(
                            "process_cert: Error adding revocation to db: \
                                {:?}",
                            e
                        ),
                    );
                    ReturnBadJSON::new(ce, cert_info.clone())
                })?;
            }
        } else {
            // add new cert to db
            action = Some(Action::New);

            let name = certificate.name.as_deref();
            let emails = certificate
                .email
                .iter()
                .map(|e| e.deref())
                .collect::<Vec<_>>();

            ca.cert_import_new(
                &armored,
                certificate.revocations.clone(),
                name,
                emails.as_slice(),
                Some(restd::CERTIFICATION_DAYS),
            )
            .map_err(|e| {
                let error = CertError::new(
                    CertStatus::InternalError,
                    format!(
                        "process_cert: Error importing Cert into db: {:?}",
                        e
                    ),
                );
                ReturnBadJSON::new(error, cert_info.clone())
            })?;
        }
    } else {
        // "check" run: set action and upload
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

    // get the last known value of delisted/inactive
    // (either from db lookup, above - or assume the default 'false')
    let delisted = if is_update {
        cert_in_ca_db.as_ref().unwrap().delisted
    } else {
        false
    };
    let inactive = if is_update {
        cert_in_ca_db.as_ref().unwrap().inactive
    } else {
        false
    };

    let certificate = Certificate {
        cert: armored,
        email: certificate.email.clone(),
        name: certificate.name.clone(),
        revocations: certificate.revocations.clone(),
        delisted: Some(delisted),
        inactive: Some(inactive),
    };

    let warn = cert_to_warn(&norm)
        .map_err(|ce| ReturnBadJSON::new(ce, Some(cert_info.clone())))?;

    Ok(ReturnGoodJSON {
        certificate,
        cert_info: cert_info_norm,
        warn,
        action,
        upload,
    })
}

pub fn process_certs(
    ca: &OpenpgpCa,
    certificate: &Certificate,
    persist: bool,
) -> Result<Vec<CertResultJSON>, ReturnError> {
    let certs = OpenpgpCa::armored_keyring_to_certs(&certificate.cert)
        .map_err(|e| {
            ReturnError::new(
                ReturnStatus::BadKeyring,
                format!(
                    "process_certs: Error parsing user-provided \
                    keyring:\n{:?}",
                    e
                ),
            )
        })?;

    // get the domain of this CA
    let my_domain = ca.get_ca_domain().map_err(|e| {
        ReturnError::new(
            ReturnStatus::InternalError,
            format!("process_certs: Error getting the CA's domain {:?}", e),
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
