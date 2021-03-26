// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::diesel::Connection;
use crate::pgp::Pgp;

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::{Cert, Packet};

use anyhow::{Context, Result};

/// Check if the CA database has a variant of the revocation
/// certificate 'rev_cert' (according to Signature::normalized_eq()).
fn check_for_equivalent_revocation(
    oca: &OpenpgpCa,
    rev_cert: &Signature,
    cert: &models::Cert,
) -> Result<bool> {
    for db_rev in oca.db().get_revocations(cert)? {
        let r = Pgp::armored_to_signature(&db_rev.revocation)
            .context("Couldn't re-armor revocation cert from CA db")?;

        if rev_cert.normalized_eq(&r) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn revocation_add(oca: &OpenpgpCa, revoc_cert_str: &str) -> Result<()> {
    // check if the exact same revocation already exists in db
    if oca.db().check_for_revocation(revoc_cert_str)? {
        return Ok(()); // this revocation is already stored -> do nothing
    }

    let mut revoc_cert = Pgp::armored_to_signature(revoc_cert_str)
        .context("Couldn't process revocation cert")?;

    // find the matching cert for this revocation certificate
    let mut cert = None;
    // - search by fingerprint, if possible
    if let Some(sig_fingerprint) = Pgp::get_revoc_issuer_fp(&revoc_cert) {
        cert = oca.db().get_cert(&sig_fingerprint.to_hex())?;
    }
    // - if match by fingerprint failed: test all certs
    if cert.is_none() {
        cert = search_revocable_cert_by_keyid(&oca, &mut revoc_cert)?;
    }

    if let Some(cert) = cert {
        let c = Pgp::armored_to_cert(&cert.pub_cert)?;

        // verify that revocation certificate validates with cert
        if validate_revocation(&c, &mut revoc_cert)? {
            if !check_for_equivalent_revocation(&oca, &revoc_cert, &cert)? {
                // update sig in DB
                let armored = Pgp::revoc_to_armored(&revoc_cert, None)
                    .context("couldn't armor revocation cert")?;

                oca.db().add_revocation(&armored, &cert)?;
            }

            Ok(())
        } else {
            let msg = format!(
                "revocation couldn't be matched to a cert: {:?}",
                revoc_cert
            );

            Err(anyhow::anyhow!(msg))
        }
    } else {
        Err(anyhow::anyhow!("couldn't find cert for this fingerprint"))
    }
}

/// verify that applying `revoc_cert` to `cert` yields a new validated
/// self revocation
fn validate_revocation(
    cert: &Cert,
    revoc_cert: &mut Signature,
) -> Result<bool> {
    let before = cert.primary_key().self_revocations().count();

    let revoked = cert.to_owned().insert_packets(revoc_cert.to_owned())?;

    let after = revoked.primary_key().self_revocations().count();

    // expecting an additional self_revocation after merging revoc_cert
    if before + 1 != after {
        return Ok(false);
    }

    // does the self revocation verify?
    let key = revoked.primary_key().key();
    Ok(revoc_cert.verify_primary_key_revocation(key, key).is_ok())
}

/// Search all certs for the one that `revoc` can revoke.
///
/// This assumes that the Signature has no issuer fingerprint.
/// So if the Signature also has no issuer KeyID, it fails to find a
/// cert.
fn search_revocable_cert_by_keyid(
    oca: &OpenpgpCa,
    mut revoc: &mut Signature,
) -> Result<Option<models::Cert>> {
    let revoc_keyhandles = revoc.get_issuers();
    if revoc_keyhandles.is_empty() {
        return Err(anyhow::anyhow!("Signature has no issuer KeyID"));
    }

    for cert in oca.user_certs_get_all()? {
        let c = Pgp::armored_to_cert(&cert.pub_cert)?;

        // require that keyid of cert and Signature issuer match
        let c_keyid = c.keyid();

        if !revoc_keyhandles.contains(&KeyHandle::KeyID(c_keyid)) {
            // ignore certs with non-matching KeyID
            continue;
        }

        // if KeyID matches, check if revocation validates
        if validate_revocation(&c, &mut revoc)? {
            return Ok(Some(cert));
        }
    }
    Ok(None)
}

pub fn revocation_apply(
    oca: &OpenpgpCa,
    revoc: models::Revocation,
) -> Result<()> {
    oca.db().get_conn().transaction::<_, anyhow::Error, _>(|| {
        let cert = oca.db().get_cert_by_id(revoc.cert_id)?;

        if let Some(mut cert) = cert {
            let sig = Pgp::armored_to_signature(&revoc.revocation)?;
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;

            let revocation: Packet = sig.into();
            let revoked = c.insert_packets(vec![revocation])?;

            cert.pub_cert = Pgp::cert_to_armored(&revoked)?;

            let mut revoc = revoc.clone();
            revoc.published = true;

            oca.db()
                .update_cert(&cert)
                .context("Couldn't update Cert")?;

            oca.db()
                .update_revocation(&revoc)
                .context("Couldn't update Revocation")?;

            Ok(())
        } else {
            Err(anyhow::anyhow!("Couldn't find cert for apply_revocation"))
        }
    })
}
