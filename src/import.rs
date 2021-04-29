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

use sequoia_net::wkd;
use sequoia_net::Policy;
use sequoia_openpgp::{Fingerprint, KeyID};

use anyhow::Result;
use tokio::runtime::Runtime;

/// Update a cert in the OpenPGP CA database via wkd.
///
/// All emails found in User IDs of the cert are looked up via WKD. For
/// all certs retrieved in that way, if they have a  matching fingerprint,
/// the cert data from wkd is merged into the existing cert (failed merges are
/// ignored silently).
pub fn update_from_wkd(oca: &OpenpgpCa, cert: &models::Cert) -> Result<()> {
    let mut rt = Runtime::new()?;

    let emails = oca.emails_get(&cert)?;

    // Collect all updates for 'cert' in 'merge'
    let mut merge = Pgp::armored_to_cert(&cert.pub_cert)?;

    for email in emails {
        let certs = rt.block_on(async move { wkd::get(&email.addr).await });

        for c in certs? {
            if c.fingerprint() == Fingerprint::from_hex(&cert.fingerprint)? {
                // If 'c' can't be merged, silently ignore the error that
                // sequoia returns
                if let Ok(m) = merge.clone().merge_public(c) {
                    merge = m;
                }
            }
        }
    }

    let mut db_update = cert.clone();
    db_update.pub_cert = Pgp::cert_to_armored(&merge)?;

    oca.db().update_cert(&db_update)?;

    Ok(())
}

/// Update a cert in the OpenPGP CA database from the "Hagrid" keyserver at
/// `keys.openpgp.org`
pub fn update_from_hagrid(oca: &OpenpgpCa, cert: &models::Cert) -> Result<()> {
    let fp = (cert.fingerprint).parse::<Fingerprint>()?;

    let c = Pgp::armored_to_cert(&cert.pub_cert)?;

    // get key from hagrid
    let mut hagrid =
        sequoia_net::KeyServer::keys_openpgp_org(Policy::Encrypted)?;

    let mut rt = Runtime::new()?;
    let update =
        rt.block_on(async move { hagrid.get(&KeyID::from(fp)).await })?;

    // Merge new certificate information into existing cert
    if let Ok(merged) = c.merge_public(update) {
        // Store merged cert in DB
        let mut db_update = cert.clone();
        db_update.pub_cert = Pgp::cert_to_armored(&merged)?;

        oca.db().update_cert(&db_update)
    } else {
        // Silently ignore potential errors from merge_public().
        Ok(())
    }
}
