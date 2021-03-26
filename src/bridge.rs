// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use std::path::Path;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::{Cert, Fingerprint};

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::pgp::Pgp;

/// Create a new Bridge (between this OpenPGP CA and a remote OpenPGP
/// CA instance)
///
/// The result of this operation is a signed public key for the remote
/// CA. Once this signature is published and available to OpenPGP
/// CA users, the bridge is in effect.
///
/// When `remote_email` or `remote_scope` are not set, they are derived
/// from the User ID in the key_file
pub fn bridge_new(
    oca: &OpenpgpCa,
    remote_key_file: &Path,
    remote_email: Option<&str>,
    remote_scope: Option<&str>,
) -> Result<(models::Bridge, Fingerprint)> {
    let remote_ca_cert =
        Cert::from_file(remote_key_file).context("Failed to read key")?;

    let remote_uids: Vec<_> = remote_ca_cert.userids().collect();

    // expect exactly one User ID in remote CA key (otherwise fail)
    if remote_uids.len() != 1 {
        return Err(anyhow::anyhow!(
            "Expected exactly one User ID in remote CA Cert",
        ));
    }

    let remote_uid = remote_uids[0].userid();

    // derive an email and domain from the User ID in the remote cert
    let (remote_cert_email, remote_cert_domain) = {
        if let Some(remote_email) = remote_uid.email()? {
            let split: Vec<_> = remote_email.split('@').collect();

            // expect remote email address with localpart "openpgp-ca"
            if split.len() != 2 || split[0] != "openpgp-ca" {
                return Err(anyhow::anyhow!(format!(
                    "Unexpected remote email {}",
                    remote_email
                )));
            }

            let domain = split[1];
            (remote_email.to_owned(), domain.to_owned())
        } else {
            return Err(anyhow::anyhow!(
                "Couldn't get email from remote CA Cert"
            ));
        }
    };

    let scope = match remote_scope {
        Some(scope) => {
            // if scope and domain don't match, warn/error?
            // (FIXME: error, unless --force parameter has been given?!)
            if scope != remote_cert_domain {
                return Err(anyhow::anyhow!(
                    "scope and domain don't match, currently unsupported"
                ));
            }

            scope
        }
        None => &remote_cert_domain,
    };

    let email = match remote_email {
        None => remote_cert_email,
        Some(email) => email.to_owned(),
    };

    let regex = domain_to_regex(scope)?;

    let regexes = vec![regex];

    let bridged =
        Pgp::bridge_to_remote_ca(oca.ca_get_cert()?, remote_ca_cert, regexes)?;

    // FIXME: transaction

    // store new bridge in DB
    let (ca_db, _) = oca.db().get_ca().context("Couldn't find CA")?.unwrap();

    let cert: models::Cert = oca.db().add_cert(
        &Pgp::cert_to_armored(&bridged)?,
        &bridged.fingerprint().to_hex(),
        None,
    )?;

    let new_bridge = models::NewBridge {
        email: &email,
        scope,
        cert_id: cert.id,
        cas_id: ca_db.id,
    };

    Ok((oca.db().insert_bridge(new_bridge)?, bridged.fingerprint()))
}

/// Create a revocation Certificate for a Bridge and apply it the our
/// copy of the remote CA's public key.
///
/// Both the revoked remote public key and the revocation cert are
/// printed to stdout.
pub fn bridge_revoke(oca: &OpenpgpCa, email: &str) -> Result<()> {
    let bridge = oca.db().search_bridge(email)?;
    if bridge.is_none() {
        return Err(anyhow::anyhow!("bridge not found"));
    }

    let bridge = bridge.unwrap();

    let (_, ca_cert) = oca.db().get_ca()?.unwrap();
    let ca_cert = Pgp::armored_to_cert(&ca_cert.priv_cert)?;

    if let Some(mut db_cert) = oca.db().get_cert_by_id(bridge.cert_id)? {
        let bridge_pub = Pgp::armored_to_cert(&db_cert.pub_cert)?;

        // make sig to revoke bridge
        let (rev_cert, cert) = Pgp::bridge_revoke(&bridge_pub, &ca_cert)?;

        let revoc_cert_arm = &Pgp::revoc_to_armored(&rev_cert, None)?;
        println!("revoc cert:\n{}", revoc_cert_arm);

        // save updated key (with revocation) to DB
        let revoked_arm = Pgp::cert_to_armored(&cert)?;
        println!("revoked remote key:\n{}", &revoked_arm);

        db_cert.pub_cert = revoked_arm;
        oca.db().update_cert(&db_cert)?;

        Ok(())
    } else {
        Err(anyhow::anyhow!("no cert found for bridge"))
    }
}

/// Make regex for trust signature from domain-name
fn domain_to_regex(domain: &str) -> Result<String> {
    // "other.org" => "<[^>]+[@.]other\\.org>$"
    // FIXME: does this imply "subdomain allowed"?

    // syntax check domain
    if !publicsuffix::Domain::has_valid_syntax(domain) {
        return Err(anyhow::anyhow!("Parameter is not a valid domainname"));
    }

    // transform domain to regex
    let escaped_domain = &domain.split('.').collect::<Vec<_>>().join("\\.");
    Ok(format!("<[^>]+[@.]{}>$", escaped_domain))
}
