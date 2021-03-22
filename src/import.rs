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

use sequoia_net::Policy;
use sequoia_openpgp::{Fingerprint, KeyID};

use anyhow::Result;

/// Pull a key from WKD and merge any updates into our local version of
/// this key
pub fn update_from_wkd(oca: &OpenpgpCa, cert: &models::Cert) -> Result<()> {
    use sequoia_net::wkd;

    use tokio::runtime::Runtime;
    let mut rt = Runtime::new()?;

    let emails = oca.emails_get(&cert)?;

    let mut merge = Pgp::armored_to_cert(&cert.pub_cert)?;

    for email in emails {
        let certs = rt.block_on(async move { wkd::get(&email.addr).await });

        for c in certs? {
            if c.fingerprint().to_hex() == cert.fingerprint {
                merge = merge.merge_public(c)?;
            }
        }
    }

    let mut updated = cert.clone();
    updated.pub_cert = Pgp::cert_to_armored(&merge)?;

    oca.db().update_cert(&updated)?;

    Ok(())
}

/// Pull a key from hagrid and merge any updates into our local version of
/// this key
pub fn update_from_hagrid(oca: &OpenpgpCa, cert: &models::Cert) -> Result<()> {
    use tokio::runtime::Runtime;
    let mut rt = Runtime::new()?;

    let mut merge = Pgp::armored_to_cert(&cert.pub_cert)?;

    // get key from hagrid
    let mut hagrid =
        sequoia_net::KeyServer::keys_openpgp_org(Policy::Encrypted)?;

    let f = (cert.fingerprint).parse::<Fingerprint>()?;
    let c = rt.block_on(async move { hagrid.get(&KeyID::from(f)).await })?;

    // update in DB
    merge = merge.merge_public(c)?;

    let mut updated = cert.clone();
    updated.pub_cert = Pgp::cert_to_armored(&merge)?;

    oca.db().update_cert(&updated)?;

    Ok(())
}
