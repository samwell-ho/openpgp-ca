// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::Signer;

use crate::backend::{Backend, CertificationBackend};
use crate::ca_secret::CaSecDb;
use crate::db::models;
use crate::pgp;
use crate::DbCa;

impl DbCa {
    /// Initialize OpenPGP CA Admin database entry.
    /// Takes a `cert` with private key material and initializes a softkey-based CA.
    ///
    /// Only one CA Admin can be configured per database.
    pub fn ca_init_softkey(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db().is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca_key = pgp::cert_to_armored_private_key(cert)?;

        self.db().ca_insert(
            models::NewCa { domainname },
            &ca_key,
            &cert.fingerprint().to_hex(),
            None,
        )
    }

    /// Initialize OpenPGP CA instance for split mode.
    /// Takes a `cert` with public key material and initializes a split-mode CA.
    pub fn ca_init_split(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db().is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca = pgp::cert_to_armored(cert)?;

        self.db().ca_insert(
            models::NewCa { domainname },
            &ca,
            &cert.fingerprint().to_hex(),
            Backend::Split.to_config().as_deref(),
        )
    }

    /// Get Cert for this CA (may contain private key material, depending on the backend)
    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db().get_ca()?;

        pgp::to_cert(cacert.priv_cert.as_bytes())
    }
}

impl CaSecDb for DbCa {
    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db.get_ca()?;

        pgp::to_cert(cacert.priv_cert.as_bytes())
    }
}

impl CertificationBackend for DbCa {
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let ca_cert = self.get_ca_cert()?; // contains private key material for DbCa
        let ca_keys = pgp::get_cert_keys(&ca_cert, None);

        for mut s in ca_keys {
            op(&mut s as &mut dyn sequoia_openpgp::crypto::Signer)?;
        }

        Ok(())
    }

    fn sign(&self, op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        let ca_cert = self.get_ca_cert()?; // contains private key material for DbCa

        // FIXME: this assumes there is exactly one signing capable subkey
        let mut signing_keypair = ca_cert
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

        op(&mut signing_keypair as &mut dyn sequoia_openpgp::crypto::Signer)?;

        Ok(())
    }
}
