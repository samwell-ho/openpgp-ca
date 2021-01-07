// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use anyhow::Context;

use sequoia_openpgp::cert::amalgamation::key::ErasedKeyAmalgamation;
use sequoia_openpgp::cert::amalgamation::{
    ComponentAmalgamation, ValidateAmalgamation,
};
use sequoia_openpgp::packet::key;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

const POLICY: &StandardPolicy = &StandardPolicy::new();

/// Human-readable, factual information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub user_ids: Vec<UserID>,

    pub primary: Key,
    pub subkeys: Vec<Key>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserID {
    pub email: Option<String>,
    pub name: Option<String>,

    /// If the UserID consists of valid utf8, this field contains the raw data
    /// (in many cases this will be redundant with the data in email + name).
    ///
    /// NOTE: this field contains user-provided utf8. It may contain html or
    /// quotes, which the frontend might need to protect itself against.
    pub raw: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocations: Option<Vec<Revocation>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Key {
    pub fingerprint: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,

    pub creation_time: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<DateTime<Utc>>,

    pub algo: String,
    pub bits: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocations: Option<Vec<Revocation>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Revocation {
    pub reason: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub information: Option<String>,

    pub time: Option<DateTime<Utc>>,
}

impl CertInfo {
    pub fn from_cert(cert: &Cert) -> Result<CertInfo, anyhow::Error> {
        let mut user_ids: Vec<UserID> = vec![];

        for userid in cert.userids() {
            let uid = UserID::from_component_amalgamation(&userid)?;

            user_ids.push(uid)
        }

        let primary = Key::from_key_amalgamation(&cert.primary_key().into());

        let subkeys = cert
            .keys()
            .subkeys()
            .map(|ka| Key::from_key_amalgamation(&ka.into()))
            .collect();

        let ci = CertInfo {
            user_ids,
            primary,
            subkeys,
        };

        Ok(ci)
    }
}

impl UserID {
    fn from_component_amalgamation(
        uid: &ComponentAmalgamation<sequoia_openpgp::packet::UserID>,
    ) -> Result<Self, anyhow::Error> {
        let email =
            uid.email().context("ERROR while converting userid.email")?;

        let name = uid.name().context("ERROR while converting userid.name")?;

        let raw = String::from_utf8(uid.value().to_vec()).ok();

        let revocations: Vec<_> = uid
            .self_revocations()
            .map(|rev| Revocation::from_sig(rev))
            .collect();

        let revocations = if revocations.is_empty() {
            None
        } else {
            Some(revocations)
        };

        Ok(UserID {
            email,
            name,
            raw,
            revocations,
        })
    }
}

impl Key {
    fn from_key_amalgamation(
        ka: &ErasedKeyAmalgamation<key::PublicParts>,
    ) -> Self {
        let (expiration, flags) =
            if let Ok(valid_sk) = ka.clone().with_policy(POLICY, None) {
                (valid_sk.key_expiration_time(), valid_sk.key_flags())
            } else {
                (None, None)
            };

        let fingerprint = ka.fingerprint().to_string();

        let creation = ka.creation_time();

        let algo = ka.pk_algo();
        let algo = algo.to_string();
        let bits = ka.key().mpis().bits().unwrap_or(0);

        let flags = if let Some(f) = flags {
            if !f.is_empty() {
                Some(format!("{:?}", f))
            } else {
                None
            }
        } else {
            None
        };

        let revocations: Vec<_> = ka
            .self_revocations()
            .map(|rev| Revocation::from_sig(rev))
            .collect();

        let revocations = if revocations.is_empty() {
            None
        } else {
            Some(revocations)
        };

        Key {
            fingerprint,
            flags,
            creation_time: creation.into(),
            expiration_time: expiration.map(|time| time.into()),
            algo,
            bits,
            revocations,
        }
    }
}

impl Revocation {
    fn from_sig(rev: &Signature) -> Self {
        let rfr = rev.reason_for_revocation();

        if let Some(r) = rfr {
            let reason = Some(r.0.to_string());

            let information = if let Ok(msg) = String::from_utf8(r.1.to_vec())
            {
                if !msg.is_empty() {
                    Some(msg)
                } else {
                    None
                }
            } else {
                Some("ERROR: bad utf8".to_string())
            };

            let rev_time = rev.signature_creation_time();
            let time = rev_time.map(|time| time.into());

            Revocation {
                reason,
                information,
                time,
            }
        } else {
            Revocation {
                reason: None,
                information: None,
                time: None,
            }
        }
    }
}
