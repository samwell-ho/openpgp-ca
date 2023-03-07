// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::rc::Rc;

use anyhow::Result;
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::Cert;

use crate::backend::CertificationBackend;
use crate::ca_secret::CaSec;
use crate::db::OcaDb;
use crate::pgp;

/// OpenPGP card backend for a split CA instance
pub(crate) struct SplitCa {
    db: Rc<OcaDb>,
}

impl SplitCa {
    pub(crate) fn new(db: Rc<OcaDb>) -> Result<Self> {
        Ok(Self { db })
    }
}

impl CaSec for SplitCa {
    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db.get_ca()?;

        pgp::to_cert(cacert.priv_cert.as_bytes())
    }
}

impl CertificationBackend for SplitCa {
    fn certify(&self, _op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        todo!()
    }

    fn sign(&self, _op: &mut dyn FnMut(&mut dyn Signer) -> Result<()>) -> Result<()> {
        todo!()
    }
}
