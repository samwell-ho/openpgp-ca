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
use serde::{Deserialize, Serialize};

use crate::ca_secret::CaSec;
use crate::db::models::NewQueue;
use crate::db::OcaDb;

#[derive(Serialize, Deserialize, Debug)]
enum QueueEntry {
    CertificationReq(CertificationReq),
}

#[derive(Serialize, Deserialize, Debug)]
struct CertificationReq {
    cert: String,
    user_ids: Vec<String>,
    days: Option<u64>,
}

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

    /// Returns an empty vec -> the certifications are created asynchronously.
    fn sign_user_ids(
        &self,
        cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Vec<Signature>> {
        // If no User IDs are requested to be signed, we can ignore the request
        if uids_certify.is_empty() {
            return Ok(vec![]);
        }

        let c = pgp::cert_to_armored(cert)?;

        let cr = CertificationReq {
            user_ids: uids_certify.iter().map(|u| u.to_string()).collect(),
            cert: c,
            days: duration_days,
        };

        // Wrap the CertificationReq in a QueueEntry and store as a JSON string.
        let qe = QueueEntry::CertificationReq(cr);
        let serialized = serde_json::to_string(&qe)?;

        let q = NewQueue {
            task: &serialized,
            done: false,
        };

        // Store the certification task in the queue
        self.db.queue_insert(q)?;

        // The Signatures cannot be generated here, so we return an empty vec
        Ok(vec![])
    }

    fn bridge_to_remote_ca(&self, _remote_ca: Cert, _scope_regexes: Vec<String>) -> Result<Cert> {
        todo!()
    }

    fn bridge_revoke(&self, _remote_ca: &Cert) -> Result<(Signature, Cert)> {
        todo!()
    }
}
