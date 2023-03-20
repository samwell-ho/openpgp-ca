// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::Signer;

use crate::backend::CertificationBackend;
use crate::pgp;

pub(crate) struct SoftkeyBackend {
    // CA private key material
    ca_cert: Cert,
}

impl SoftkeyBackend {
    pub(crate) fn new(ca_cert: Cert) -> Self {
        Self { ca_cert }
    }
}

impl CertificationBackend for SoftkeyBackend {
    fn certify(&self, op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        let ca_keys = pgp::get_cert_keys(&self.ca_cert, None);

        for mut s in ca_keys {
            op(&mut s as &mut dyn Signer)?;
        }

        Ok(())
    }

    fn sign(&self, op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        // FIXME: this assumes there is exactly one signing capable subkey
        let mut signing_keypair = self
            .ca_cert
            .clone()
            .keys()
            .secret()
            .with_policy(pgp::SP, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;

        op(&mut signing_keypair as &mut dyn Signer)?;

        Ok(())
    }
}
