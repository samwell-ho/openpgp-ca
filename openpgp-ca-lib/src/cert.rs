// Copyright 2019-2022 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::{CertificationStatus, OpenpgpCa};
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::Cert;

use anyhow::{Context, Result};

use std::collections::{HashMap, HashSet};
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
        Pgp::make_user_cert(emails, name, password).context("make_user_cert failed")?;

    // CA certifies user cert
    let user_certified = sign_cert_emails(oca, &user_key, Some(emails), duration_days)
        .context("sign_user_emails failed")?;

    // User tsigns CA cert
    let ca_cert = oca.ca_get_cert_pub()?;
    let tsigned_ca =
        Pgp::tsign(ca_cert, &user_key, pass.as_deref()).context("tsign for CA cert failed")?;

    let tsigned_ca = Pgp::cert_to_armored_private_key(&tsigned_ca)?;

    // Store tsig for the CA cert
    oca.secret().ca_import_tsig(tsigned_ca.as_bytes())?;

    // Store new user cert in DB
    let user_cert = Pgp::cert_to_armored(&user_certified)?;
    let user_revoc = Pgp::revoc_to_armored(&user_revoc, None)?;

    oca.db()
        .user_add(
            name,
            (&user_cert, &user_key.fingerprint().to_hex()),
            emails,
            &[user_revoc],
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
    user_cert: &[u8],
    revoc_certs: &[&[u8]],
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
) -> Result<()> {
    let user_cert =
        Pgp::to_cert(user_cert).context("cert_import_new: Couldn't process user cert.")?;

    let fp = user_cert.fingerprint().to_hex();

    if let Some(_exists) = oca
        .db()
        .cert_by_fp(&fp)
        .context("cert_import_new(): get_cert() check by fingerprint failed")?
    {
        // import_new is not intended for certs we already have a version of
        return Err(anyhow::anyhow!(
            "A key with this fingerprint already exists in the DB.\nTo update it, use the 'user update' command."
        ));
    }

    // Sign user cert with CA key (only the User IDs that have been specified)
    let certified = sign_cert_emails(oca, &user_cert, Some(emails), duration_days)
        .context("sign_cert_emails() failed")?;

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
    let pub_cert =
        Pgp::cert_to_armored(&certified).context("cert_import_new: Couldn't re-armor key")?;

    // (filter revocations through Sequoia, to get (re-)armored representations)
    let rev_sig: Result<Vec<_>> = revoc_certs.iter().map(|r| Pgp::to_signature(r)).collect();
    let rev_armored: Result<Vec<_>> = rev_sig?
        .iter()
        .map(|s| Pgp::revoc_to_armored(s, None))
        .collect();

    oca.db()
        .user_add(name.as_deref(), (&pub_cert, &fp), emails, &rev_armored?)
        .context("Couldn't insert user")?;

    Ok(())
}

pub fn cert_import_update(oca: &OpenpgpCa, cert: &[u8]) -> Result<()> {
    let cert_new = Pgp::to_cert(cert).context("cert_import_update: couldn't process cert")?;

    let fp = cert_new.fingerprint().to_hex();

    if let Some(mut db_cert) = oca
        .db()
        .cert_by_fp(&fp)
        .context("cert_import_update(): get_cert() check by fingerprint failed")?
    {
        // merge existing and new public key
        let cert_old = Pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        let updated = cert_old.merge_public(cert_new)?;
        let armored = Pgp::cert_to_armored(&updated)?;

        db_cert.pub_cert = armored;
        oca.db().cert_update(&db_cert)
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
    let threshold_time =
        SystemTime::now() + Duration::from_secs(threshold_days * Pgp::SECONDS_IN_DAY);

    let ca = oca.ca_get_cert_pub()?;

    for db_cert in oca
        .db()
        .certs()?
        .iter()
        // ignore "inactive" Certs
        .filter(|c| !c.inactive)
    {
        let c = Pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        let mut recertify = Vec::new();

        for uid in c.userids() {
            // find valid certifications by the CA on this uid
            let ca_certifications = Pgp::valid_certifications_by(&uid, &c, ca.clone());

            let sig_valid_past_threshold = |sig: &Signature| {
                if let Some(expiration) = sig.signature_expiration_time() {
                    expiration > threshold_time
                } else {
                    true // signature has no expiration time
                }
            };

            // A new certification is created if
            // a) a valid certification by the CA exists, but
            // b) no existing certification is valid for longer than
            // `threshold_days`
            if !ca_certifications.is_empty()
                && !ca_certifications.iter().any(sig_valid_past_threshold)
            {
                // A new certification for this uid should be created
                recertify.push(uid.userid());
            }
        }
        if !recertify.is_empty() {
            // Make new certifications for the User IDs identified above
            let recertified =
                oca.secret()
                    .sign_user_ids(&c, &recertify[..], Some(validity_days))?;

            // update cert in db
            let mut cert_update = db_cert.clone();
            cert_update.pub_cert = Pgp::cert_to_armored(&recertified)?;
            oca.db().cert_update(&cert_update)?;
        }
    }

    Ok(())
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
        let c = Pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        // Notify only certs that are alive now, but not alive at
        // 'expiry_test'.
        if c.with_policy(Pgp::SP, None)?.alive().is_ok()
            && c.with_policy(Pgp::SP, expiry_test)?.alive().is_err()
        {
            res.insert(db_cert, Pgp::get_expiry(&c)?);
        }
    }

    Ok(res)
}

pub fn cert_check_ca_sig(oca: &OpenpgpCa, cert: &models::Cert) -> Result<CertificationStatus> {
    let c = Pgp::to_cert(cert.pub_cert.as_bytes())?;
    let ca = oca.ca_get_cert_pub()?;

    let mut certified = vec![];
    let mut uncertified = vec![];

    for uid in c.userids() {
        if Pgp::valid_certifications_by(&uid, &c, ca.clone()).is_empty() {
            uncertified.push(uid.userid().clone());
        } else {
            certified.push(uid.userid().clone());
        }
    }

    Ok(CertificationStatus {
        certified,
        uncertified,
    })
}

pub fn cert_check_tsig_on_ca(oca: &OpenpgpCa, cert: &models::Cert) -> Result<bool> {
    let ca = oca.ca_get_cert_pub()?;
    let tsigs = Pgp::get_trust_sigs(&ca)?;

    let user_cert = Pgp::to_cert(cert.pub_cert.as_bytes())?;

    Ok(tsigs.iter().any(|t| {
        t.issuer_fingerprints()
            .any(|fp| fp == &user_cert.fingerprint())
    }))
}

/// CA certifies either all or a subset of User IDs of cert.
///
/// 'emails_filter' (if not None) specifies the subset of User IDs to
/// certify.
fn sign_cert_emails(
    oca: &OpenpgpCa,
    cert: &Cert,
    emails_filter: Option<&[&str]>,
    duration_days: Option<u64>,
) -> Result<Cert> {
    let fp_ca = oca.ca_get_cert_pub()?.fingerprint();

    let mut uids = Vec::new();

    // make sure we find suitable user ids to certify for each passed email
    let mut unused_email: HashSet<&str> = if let Some(emails) = emails_filter {
        emails.iter().copied().collect()
    } else {
        HashSet::new()
    };

    for uid in cert.userids() {
        // check if this uid already has a valid signature by ca_cert.
        // if yes, don't add another one.
        if !uid
            .clone()
            .with_policy(Pgp::SP, None)?
            .certifications()
            .any(|s| s.issuer_fingerprints().any(|fp| fp == &fp_ca))
        {
            let userid = uid.userid();
            let uid_addr = userid
                .email_normalized()?
                .expect("email normalization failed");

            // Certify this User ID if we
            // a) have no filter-list, or
            // b) if the User ID is specified in the filter-list.
            if emails_filter.is_none() || emails_filter.unwrap().contains(&uid_addr.as_str()) {
                unused_email.remove(uid_addr.as_str());

                uids.push(userid);
            }
        }
    }

    // Print a message when specified email addresses couldn't be found and certified on a User ID.
    //
    // FIXME: this information should not be printed here, but returned to the user of the library
    // as a list
    if !unused_email.is_empty() {
        let mut unused: Vec<_> = unused_email.into_iter().collect();
        unused.sort_unstable();

        println!(
            "Warning: Couldn't find a User ID to certify for '{}' in {}",
            unused.join(", "),
            cert.fingerprint()
        );
    }

    oca.secret().sign_user_ids(cert, &uids, duration_days)
}
