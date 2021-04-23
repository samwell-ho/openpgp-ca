// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::policy::StandardPolicy;

use anyhow::{Context, Result};

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub fn user_new(
    oca: &OpenpgpCa,
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
    password: bool,
    output_format_minimal: bool,
) -> Result<()> {
    // Generate new user key
    let (user_key, user_revoc, pass) =
        Pgp::make_user_cert(emails, name, password)
            .context("make_user_cert failed")?;

    // CA certifies user cert
    let user_certified = oca
        .secret()
        .sign_cert_emails(&user_key, Some(emails), duration_days)
        .context("sign_user_emails failed")?;

    // User tsigns CA cert
    let ca_cert = oca.ca_get_cert_pub()?;
    let tsigned_ca = Pgp::tsign(ca_cert, &user_key, pass.as_deref())
        .context("tsign for CA cert failed")?;

    let tsigned_ca = Pgp::cert_to_armored_private_key(&tsigned_ca)?;

    // Store new user cert (and tsig for CA key) in DB
    let user_cert = Pgp::cert_to_armored(&user_certified)?;
    let user_revoc = Pgp::revoc_to_armored(&user_revoc, None)?;

    oca.db()
        .add_user(
            name,
            (&user_cert, &user_key.fingerprint().to_hex()),
            emails,
            &[user_revoc],
            Some(&tsigned_ca),
        )
        .context("Failed to insert new user into DB")?;

    // the private key needs to be handed over to the user -> print it
    let private = Pgp::cert_to_armored_private_key(&user_certified)?;

    if output_format_minimal {
        // short format (convenient for use with the 'pass' tool)
        if let Some(pass) = pass {
            println!("{}", pass);
        }
        println!("{}", private);
    } else {
        println!("new user key for {}:\n{}", name.unwrap_or(""), private);
        if let Some(pass) = pass {
            println!("Password for this key: '{}'.\n", pass);
        } else {
            println!("No password set for this key.\n");
        }
    }

    Ok(())
}

pub fn cert_import_new(
    oca: &OpenpgpCa,
    user_cert: &str,
    revoc_certs: Vec<String>,
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
) -> Result<()> {
    let user_cert = Pgp::armored_to_cert(user_cert)
        .context("cert_import_new: couldn't process user cert")?;

    let fp = user_cert.fingerprint().to_hex();

    if let Some(_exists) = oca.db().get_cert(&fp).context(
        "cert_import_new: error while checking for existing cert with the \
        same fingerprint",
    )? {
        // import_new is not intended for certs we already have a version of
        return Err(anyhow::anyhow!(
            "A cert with this fingerprint already exists in the DB"
        ));
    }

    // Sign user cert with CA key (only the User IDs that have been specified)
    let certified = oca
        .secret()
        .sign_cert_emails(&user_cert, Some(emails), duration_days)
        .context("sign_user_emails failed")?;

    // use name from User IDs, if no name was passed
    let name = match name {
        Some(name) => Some(name.to_owned()),
        None => {
            let userids: Vec<_> = user_cert.userids().collect();
            if userids.len() == 1 {
                userids[0].userid().name()?
            } else {
                None
            }
        }
    };

    // Insert new user cert into DB
    let pub_cert = Pgp::cert_to_armored(&certified)
        .context("cert_import_new: couldn't re-armor key")?;

    oca.db()
        .add_user(
            name.as_deref(),
            (&pub_cert, &fp),
            &emails,
            &revoc_certs,
            None,
        )
        .context("Couldn't insert user")?;

    Ok(())
}

pub fn cert_import_update(oca: &OpenpgpCa, cert: &str) -> Result<()> {
    let cert_new = Pgp::armored_to_cert(cert)
        .context("cert_import_update: couldn't process cert")?;

    let fp = cert_new.fingerprint().to_hex();

    if let Some(mut db_cert) = oca.db().get_cert(&fp).context(
        "cert_import_update: error while checking for \
            existing cert with the same fingerprint",
    )? {
        // merge existing and new public key
        let cert_old = Pgp::armored_to_cert(&db_cert.pub_cert)?;

        let updated = cert_old.merge_public(cert_new)?;
        let armored = Pgp::cert_to_armored(&updated)?;

        db_cert.pub_cert = armored;
        oca.db().update_cert(&db_cert)
    } else {
        Err(anyhow::anyhow!(
            "No cert with this fingerprint found in DB, cannot update"
        ))
    }
}

pub fn certs_refresh_ca_certifications(
    oca: &OpenpgpCa,
    threshold_days: u64,
    validity_days: u64,
) -> Result<()> {
    oca.db().transaction(|| {
        let ca_fp = oca.ca_get_cert_pub()?.fingerprint();

        let threshold_secs = threshold_days * 24 * 60 * 60;
        let threshold_time =
            SystemTime::now() + Duration::new(threshold_secs, 0);

        for db_cert in oca
            .db()
            .get_certs()?
            .iter()
            // ignore "inactive" Certs
            .filter(|c| !c.inactive)
        {
            let c = Pgp::armored_to_cert(&db_cert.pub_cert)?;
            let mut uids_to_recert = Vec::new();

            for uid in c.userids() {
                let ca_certifications: Vec<_> = uid
                    .certifications()
                    .filter(|c| c.issuer_fingerprints().any(|fp| *fp == ca_fp))
                    .collect();

                let sig_valid_past_threshold = |c: &&Signature| {
                    let expiration = c.signature_expiration_time();
                    expiration.is_none()
                        || (expiration.unwrap() > threshold_time)
                };

                // a new certification is created if certifications by the
                // CA exist, but none of the existing certifications are
                // valid for longer than `threshold_days`
                if !ca_certifications.is_empty()
                    && !ca_certifications.iter().any(sig_valid_past_threshold)
                {
                    // make a new certification for this uid
                    uids_to_recert.push(uid.userid());
                }
            }
            if !uids_to_recert.is_empty() {
                // make new certifications for "uids_to_update"
                let recertified = oca.secret().sign_user_ids(
                    &c,
                    &uids_to_recert[..],
                    Some(validity_days),
                )?;

                // update cert in db
                let mut cert_update = db_cert.clone();
                cert_update.pub_cert = Pgp::cert_to_armored(&recertified)?;
                oca.db().update_cert(&cert_update)?;
            }
        }

        Ok(())
    })
}

/// Return a list of Certs that are alive now, but will not be alive
/// anymore a number of 'days' in the future.
///
/// The purpose is to have a list of Certs whose users can be notified that
/// their Certs will expire soon, in case they want to extend the
/// expiration date.
pub fn certs_expired(
    oca: &OpenpgpCa,
    days: u64,
) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
    let mut res = HashMap::new();

    let days = Duration::new(60 * 60 * 24 * days, 0);
    let expiry_test = SystemTime::now().checked_add(days).unwrap();

    let certs = oca.user_certs_get_all().context("couldn't load certs")?;

    for db_cert in certs {
        let c = Pgp::armored_to_cert(&db_cert.pub_cert)?;

        let p = StandardPolicy::new();

        // Notify only certs that are alive now, but not alive at
        // 'expiry_test'.
        if c.with_policy(&p, None)?.alive().is_ok()
            && c.with_policy(&p, expiry_test)?.alive().is_err()
        {
            res.insert(db_cert, Pgp::get_expiry(&c)?);
        }
    }

    Ok(res)
}

pub fn cert_check_certifications(
    oca: &OpenpgpCa,
    cert: &models::Cert,
) -> Result<(Vec<UserID>, bool)> {
    let sig_from_ca = oca
        .cert_check_ca_sig(&cert)
        .context("Failed while checking CA sig")?;

    let tsig_on_ca = oca
        .cert_check_tsig_on_ca(&cert)
        .context("Failed while checking tsig on CA")?;

    Ok((sig_from_ca, tsig_on_ca))
}

pub fn cert_check_ca_sig(
    oca: &OpenpgpCa,
    cert: &models::Cert,
) -> Result<Vec<UserID>> {
    let c = Pgp::armored_to_cert(&cert.pub_cert)?;

    let ca = oca.ca_get_cert_pub()?;

    let mut res = Vec::new();
    let policy = StandardPolicy::new();

    for uid in c.userids() {
        let signed_by_ca = uid
            .clone()
            .with_policy(&policy, None)?
            .bundle()
            .certifications()
            .iter()
            .any(|s| s.issuer_fingerprints().any(|f| f == &ca.fingerprint()));

        if signed_by_ca {
            res.push(uid.userid().clone());
        }
    }

    Ok(res)
}

pub fn cert_check_tsig_on_ca(
    oca: &OpenpgpCa,
    cert: &models::Cert,
) -> Result<bool> {
    let ca = oca.ca_get_cert_pub()?;
    let tsigs = Pgp::get_trust_sigs(&ca)?;

    let user_cert = Pgp::armored_to_cert(&cert.pub_cert)?;

    Ok(tsigs.iter().any(|t| {
        t.issuer_fingerprints()
            .any(|fp| fp == &user_cert.fingerprint())
    }))
}
