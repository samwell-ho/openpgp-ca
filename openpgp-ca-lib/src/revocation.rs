// Copyright 2019-2023 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;

use crate::db::models;
use crate::pgp;

/// Check if the CA database has a variant of the revocation
/// certificate 'revocation' (according to Signature::normalized_eq()).
pub(crate) fn check_for_equivalent_revocation(
    revocations: Vec<models::Revocation>,
    revocation: &Signature,
) -> Result<bool> {
    for db_rev in revocations {
        let r = pgp::to_signature(db_rev.revocation.as_bytes())
            .context("Couldn't re-armor revocation cert from CA db")?;

        if revocation.normalized_eq(&r) {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify that `revoc_cert` can be used to revoke the primary key of `cert`.
pub(crate) fn validate_revocation(cert: &Cert, revocation: &mut Signature) -> Result<bool> {
    let before = cert.primary_key().self_revocations().count();

    let revoked = cert.to_owned().insert_packets(revocation.to_owned())?;

    let after = revoked.primary_key().self_revocations().count();

    // expecting an additional self_revocation after merging revoc_cert
    if before + 1 != after {
        return Ok(false);
    }

    // Does the revocation verify?
    let key = revoked.primary_key().key();
    Ok(revocation.verify_primary_key_revocation(key, key).is_ok())
}

/// Search a matching cert for `revoc` based on KeyID equality.
///
/// (This is used when the revocation has no issuer fingerprint)
pub(crate) fn search_revocable_cert_by_keyid(
    certs: Vec<models::Cert>,
    revoc: &mut Signature,
) -> Result<Option<models::Cert>> {
    let revoc_keyhandles = revoc.get_issuers();
    if revoc_keyhandles.is_empty() {
        return Err(anyhow::anyhow!("Signature has no issuer KeyID"));
    }

    for db_cert in certs {
        let c = pgp::to_cert(db_cert.pub_cert.as_bytes())?;

        // require that keyid of cert and Signature issuer match
        let c_keyid = c.keyid();

        if !revoc_keyhandles.contains(&KeyHandle::KeyID(c_keyid)) {
            // ignore certs with non-matching KeyID
            continue;
        }

        // if KeyID matches, check if revocation validates
        if validate_revocation(&c, revoc)? {
            return Ok(Some(db_cert));
        }
    }
    Ok(None)
}
