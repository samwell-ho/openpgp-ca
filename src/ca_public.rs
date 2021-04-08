// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::{DbCa, OpenpgpCa};
use crate::pgp::Pgp;

use sequoia_openpgp::Cert;

use anyhow::{Context, Result};

/// abstraction of operations that only need public CA key material
pub trait CaPub {
    fn get_ca_email(&self, oca: &OpenpgpCa) -> Result<String>;
    fn get_ca_domain(&self, oca: &OpenpgpCa) -> Result<String>;
    fn ca_get_pubkey_armored(&self, oca: &OpenpgpCa) -> Result<String>;
    fn ca_get_cert_pub(&self, oca: &OpenpgpCa) -> Result<Cert>;
}

impl CaPub for DbCa {
    fn get_ca_email(&self, oca: &OpenpgpCa) -> Result<String> {
        let cert = self.ca_get_cert_pub(oca)?;
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

    fn get_ca_domain(&self, oca: &OpenpgpCa) -> Result<String> {
        let cert = self.ca_get_cert_pub(oca)?;
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

    fn ca_get_pubkey_armored(&self, oca: &OpenpgpCa) -> Result<String> {
        let cert = self.ca_get_cert_pub(oca)?;
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    fn ca_get_cert_pub(&self, oca: &OpenpgpCa) -> Result<Cert> {
        Ok(oca.ca_get_cert_priv()?.strip_secret_key_material())
    }
}
