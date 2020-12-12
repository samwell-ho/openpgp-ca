// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use chrono::{DateTime, Utc};
use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum CertResultJSON {
    Good(ReturnGoodJSON),
    Bad(ReturnBadJSON),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Action {
    New,     // this cert can be imported
    Merge,   // this cert can be imported as an update
    Revoked, // revoked cert, importing is recommended
}

/// A container for information about a "good" Cert.
///
/// `cert_info` contains factual information about a cert.
///
/// Later we may add e.g. `cert_lints` (... ?)
#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnGoodJSON {
    /// OpenPGP CA representation of a Cert (armored cert + metadata)
    pub certificate: Certificate,

    /// Factual information about the properties of an OpenPGP Cert
    pub cert_info: CertInfo,

    /// +later: cert_lints (e.g. expiry warnings, deprecated crypto, ...)

    /// action ("new" or "update")
    pub action: Option<Action>,
}

/// A container for information about a "bad" Cert.
#[derive(Serialize, Deserialize)]
pub struct ReturnBadJSON {
    pub error: ReturnError,
    pub cert_info: Option<CertInfo>,
}

impl ReturnBadJSON {
    pub fn new(error: ReturnError, cert_info: Option<CertInfo>) -> Self {
        Self { error, cert_info }
    }
}

/// Human-readable, factual information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub fingerprint: String,

    pub user_ids: Vec<String>,

    pub primary_creation_time: DateTime<Utc>,
    // pk_algo: String,

    // pk_size: usize,

    // subkeys: Vec<SubkeyInfo>,

    // revocation status
}

// #[derive(Debug, Serialize, Deserialize)]
// struct SubkeyInfo {}

impl From<&Cert> for CertInfo {
    fn from(cert: &Cert) -> Self {
        let emails = cert
            .userids()
            .filter_map(|uid| {
                uid.email().expect("ERROR while converting user_id")
            })
            .collect();

        CertInfo {
            fingerprint: cert.fingerprint().to_hex(),
            user_ids: emails,
            primary_creation_time: cert.primary_key().creation_time().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub email: Vec<String>,

    pub name: Option<String>,

    // as input, cert may contain multiple certs.
    // as output, this will always contain exactly one cert.
    pub cert: String,

    pub revocations: Vec<String>,

    // doesn't need to be provided (default: false),
    // but will always be returned
    pub delisted: Option<bool>,

    // doesn't need to be provided (default: false),
    // but will always be returned
    pub inactive: Option<bool>,
}

impl Certificate {
    pub fn from(
        cert: &models::Cert,
        user: &models::User,
        emails: &[models::CertEmail],
        rev: &[models::Revocation],
    ) -> Self {
        let r: Vec<_> = rev.iter().map(|r| r.revocation.clone()).collect();
        let e: Vec<_> = emails.iter().map(|e| e.addr.clone()).collect();

        Certificate {
            email: e,
            name: user.name.clone(),
            cert: cert.pub_cert.clone(),
            revocations: r,
            delisted: Some(cert.delisted),
            inactive: Some(cert.inactive),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnError {
    pub status: ReturnStatus,
    pub msg: String,
}

impl ReturnError {
    pub fn new(status: ReturnStatus, msg: String) -> Self {
        ReturnError { status, msg }
    }

    pub fn bad_req(
        status: ReturnStatus,
        msg: String,
    ) -> BadRequest<Json<ReturnError>> {
        let err = ReturnError::new(status, msg);
        BadRequest(Some(Json(err)))
    }

    pub fn bad_req_ci(
        status: ReturnStatus,
        msg: String,
        ci: Option<CertInfo>,
    ) -> BadRequest<Json<ReturnBadJSON>> {
        let re = ReturnError::new(status, msg);
        let rbj = ReturnBadJSON::new(re, ci);
        BadRequest(Some(Json(rbj)))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ReturnStatus {
    /// A private OpenPGP Key was provided - this is not allowed
    PrivateKey,

    /// The provided OpenPGP Key exceeds the allowed size limit
    KeySizeLimit,

    /// Sequoia's standard policy rejects this key.
    /// This probably means the key is using very old, broken crypto.
    Policy(String),

    /// Sequoia's standard policy rejects this key, but allows it when SHA1
    /// is allowed.
    ///
    /// This means the key can be "fixed" by replacing the SHA1 hashes.
    PolicySha1(String),

    /// General problem with an OpenPGP Key
    BadKey,

    /// Problem with a provided email address
    BadEmail,

    /// The OpenPGP key does not include a user_id that corresponds to an
    /// email address that was provided in "Certificate".
    ///
    /// This probably means that the user provided an OpenPGP key that is
    /// not suitable for use in this service.
    KeyMissingLocalUserId,

    /// A problem occurred that wasn't caused by external data.
    ///
    /// This should not happen - if it happens, it should probably be
    /// handled similar to HTTP 500, and investigated.
    InternalError,

    /// requested entity couldn't be found (e.g. lookup by fingerprint)
    NotFound,
}
