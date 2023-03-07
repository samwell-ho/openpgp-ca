// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Result;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::Cert;

use crate::ca_secret::CaSec;
use crate::db::OcaDb;

/// OpenPGP card backend for a split CA instance
pub(crate) struct SplitCa {
    #[allow(dead_code)]
    db: Rc<OcaDb>,
}

impl SplitCa {
    pub(crate) fn new(db: Rc<OcaDb>) -> Result<Self> {
        Ok(Self { db })
    }
}

impl CaSec for SplitCa {
    fn ca_generate_revocations(&self, _output: PathBuf) -> Result<()> {
        todo!()
    }

    // This operation is currently only used by "keylist export".
    // The user should run this command on the backing CA instance
    // that has access to the CA key material.
    fn sign_detached(&self, _data: &[u8]) -> Result<String> {
        Err(anyhow::anyhow!(
            "Operation is not supported on a split-mode CA instance. Please perform it on your backing CA instance."
        ))
    }

    fn sign_user_ids(
        &self,
        _cert: &Cert,
        _uids_certify: &[&UserID],
        _duration_days: Option<u64>,
    ) -> Result<Cert> {
        todo!()
    }

    fn bridge_to_remote_ca(&self, _remote_ca: Cert, _scope_regexes: Vec<String>) -> Result<Cert> {
        todo!()
    }

    fn bridge_revoke(&self, _remote_ca: &Cert) -> Result<(Signature, Cert)> {
        todo!()
    }
}
