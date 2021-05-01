// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::DbCa;
use crate::pgp::Pgp;

use sequoia_openpgp::Cert;

use anyhow::{Context, Result};

/// abstraction of operations that only need public CA key material
pub trait CaPub {
    fn get_ca_email(&self) -> Result<String>;
    fn get_ca_domain(&self) -> Result<String>;
    fn ca_get_pubkey_armored(&self) -> Result<String>;
    fn ca_get_cert_pub(&self) -> Result<Cert>;
}

impl CaPub for DbCa {
    fn get_ca_email(&self) -> Result<String> {
        let email = self.ca_userid()?.email()?;

        if let Some(email) = email {
            Ok(email)
        } else {
            Err(anyhow::anyhow!("CA user_id has no email"))
        }
    }

    fn get_ca_domain(&self) -> Result<String> {
        let email = self.get_ca_email()?;
        let email_split: Vec<_> = email.split('@').collect();

        if email_split.len() == 2 {
            Ok(email_split[1].to_owned())
        } else {
            Err(anyhow::anyhow!("Failed to split domain from CA email"))
        }
    }

    fn ca_get_pubkey_armored(&self) -> Result<String> {
        let cert = self.ca_get_cert_pub()?;
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("Failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    fn ca_get_cert_pub(&self) -> Result<Cert> {
        let (_, cacert) = self.db().get_ca()?;

        let cert = Pgp::armored_to_cert(&cacert.priv_cert)?;
        Ok(cert.strip_secret_key_material())
    }
}
