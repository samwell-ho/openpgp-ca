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
) -> Result<models::User> {
    let ca_cert = oca.ca_get_cert_pub()?;

    // make user cert (signed by CA)
    let (user_cert, revoc, pass) = Pgp::make_user_cert(emails, name, password)
        .context("make_user failed")?;

    // sign user key with CA key
    let certified = oca
        .sign_user_emails(&user_cert, Some(emails), duration_days)
        .context("sign_user failed")?;

    // user tsigns CA key
    let tsigned_ca = Pgp::tsign(ca_cert, &user_cert, pass.as_deref())
        .context("failed: user tsigns CA")?;

    let tsigned_ca_armored = Pgp::cert_to_armored_private_key(&tsigned_ca)?;

    let pub_key = &Pgp::cert_to_armored(&certified)?;
    let revoc = Pgp::revoc_to_armored(&revoc, None)?;

    oca.db().transaction(|| {
        let res = oca.db().add_user(
            name,
            (pub_key, &user_cert.fingerprint().to_hex()),
            emails,
            &[revoc],
            Some(&tsigned_ca_armored),
        );

        if res.is_err() {
            eprint!("{:?}", res);
            return Err(anyhow::anyhow!("Couldn't insert user"));
        }

        // the private key needs to be handed over to the user, print for now
        println!(
            "new user key for {}:\n{}",
            name.unwrap_or(""),
            &Pgp::cert_to_armored_private_key(&certified)?
        );
        if let Some(pass) = pass {
            println!("Password for this key: '{}'.\n", pass);
        } else {
            println!("No password set for this key.\n");
        }
        // --

        res
    })
}

pub fn cert_import_new(
    oca: &OpenpgpCa,
    key: &str,
    revoc_certs: Vec<String>,
    name: Option<&str>,
    emails: &[&str],
    duration_days: Option<u64>,
) -> Result<()> {
    let c = Pgp::armored_to_cert(key)
        .context("cert_import_new: couldn't process key")?;

    let fingerprint = &c.fingerprint().to_hex();

    let exists = oca.db().get_cert(fingerprint).context(
        "cert_import_new: error while checking for \
            existing cert with the same fingerprint",
    )?;

    if exists.is_some() {
        return Err(anyhow::anyhow!(
            "A cert with this fingerprint already exists in the DB"
        ));
    }

    // sign user key with CA key (only the User IDs that have been specified)
    let certified = oca
        .sign_user_emails(&c, Some(emails), duration_days)
        .context("sign_user_emails failed")?;

    // use name from User IDs, if no name was passed
    let name = match name {
        Some(name) => Some(name.to_owned()),
        None => {
            let userids: Vec<_> = c.userids().collect();
            if userids.len() == 1 {
                let userid = &userids[0];
                userid.userid().name()?
            } else {
                None
            }
        }
    };

    let pub_key = &Pgp::cert_to_armored(&certified)
        .context("cert_import_new: couldn't re-armor key")?;

    oca.db().transaction(|| {
        let res = oca.db().add_user(
            name.as_deref(),
            (pub_key, fingerprint),
            &emails,
            &revoc_certs,
            None,
        );

        if res.is_err() {
            eprint!("{:?}", res);
            return Err(anyhow::anyhow!("Couldn't insert user"));
        }

        Ok(())
    })
}

pub fn cert_import_update(oca: &OpenpgpCa, key: &str) -> Result<()> {
    let cert_new = Pgp::armored_to_cert(key)
        .context("cert_import_new: couldn't process key")?;

    let fingerprint = &cert_new.fingerprint().to_hex();

    let exists = oca.db().get_cert(fingerprint).context(
        "cert_import_update: error while checking for \
            existing cert with the same fingerprint",
    )?;

    if let Some(mut cert) = exists {
        // merge existing and new public key
        let cert_old = Pgp::armored_to_cert(&cert.pub_cert)?;

        let updated = cert_old.merge_public(cert_new)?;
        let armored = Pgp::cert_to_armored(&updated)?;

        cert.pub_cert = armored;
        oca.db().update_cert(&cert)?;
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "No cert with this fingerprint exists in the DB, cannot \
                update"
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

        for cert in oca
            .db()
            .get_certs()?
            .iter()
            // ignore "inactive" Certs
            .filter(|c| !c.inactive)
        {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;
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
                let recertified = oca.sign_user_ids(
                    &c,
                    &uids_to_recert[..],
                    Some(validity_days),
                )?;

                // update cert in db
                let mut cert_update = cert.clone();
                cert_update.pub_cert = Pgp::cert_to_armored(&recertified)?;
                oca.cert_update(&cert_update)?;
            }
        }

        Ok(())
    })
}

pub fn certs_expired(
    oca: &OpenpgpCa,
    days: u64,
) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
    let mut map = HashMap::new();

    let days = Duration::new(60 * 60 * 24 * days, 0);
    let expiry_test = SystemTime::now().checked_add(days).unwrap();

    let certs = oca.user_certs_get_all().context("couldn't load certs")?;

    for cert in certs {
        let c = Pgp::armored_to_cert(&cert.pub_cert)?;

        // only consider (and thus potentially notify as "expiring") certs
        // that are alive now
        if c.with_policy(&StandardPolicy::new(), None)?
            .alive()
            .is_err()
        {
            continue;
        }

        let exp = Pgp::get_expiry(&c)?;
        let alive = c
            .with_policy(&StandardPolicy::new(), expiry_test)?
            .alive()
            .is_ok();

        if !alive {
            map.insert(cert, exp);
        }
    }

    Ok(map)
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
