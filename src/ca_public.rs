// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::pgp::Pgp;

use anyhow::{Context, Result};

pub fn get_ca_email(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let uids: Vec<_> = cert.userids().collect();

    if uids.len() != 1 {
        return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
    }

    let email = &uids[0].userid().email()?;

    if let Some(email) = email {
        Ok(email.clone())
    } else {
        Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
    }
}

pub fn get_ca_domain(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let uids: Vec<_> = cert.userids().collect();

    if uids.len() != 1 {
        return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
    }

    let email = &uids[0].userid().email()?;

    if let Some(email) = email {
        let split: Vec<_> = email.split('@').collect();

        if split.len() == 2 {
            Ok(split[1].to_owned())
        } else {
            Err(anyhow::anyhow!(
                "ERROR: Error while splitting domain from CA user_id "
            ))
        }
    } else {
        Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
    }
}

pub fn ca_get_pubkey_armored(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let ca_pub = Pgp::cert_to_armored(&cert)
        .context("failed to transform CA key to armored pubkey")?;

    Ok(ca_pub)
}
