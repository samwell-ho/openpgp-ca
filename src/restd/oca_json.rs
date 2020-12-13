// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

use crate::models;
use crate::restd::certinfo::CertInfo;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum CertResultJSON {
    Good(ReturnGoodJSON),
    Bad(ReturnBadJSON),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Action {
    /// This cert can be imported, it is "new" to this CA:
    /// We don't have a cert with this fingerprint yet.
    ///
    /// The UI should instruct the user to double-check this cert and
    /// explicitly confirm that it should be uploaded (and thus certified
    /// by the CA).
    New,

    /// This cert can be imported as an update, we already have a cert
    /// with this fingerprint.
    ///
    /// The UI should recommend that this cert be uploaded.
    ///
    /// The existing and new version of the cert will be merged.
    Merge,

    /// This is a revoked cert.
    ///
    /// The UI should recommended uploading this cert (even if we don't
    /// have a cert with this fingerprint yet).
    Revoked,
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

impl From<ReturnError> for ReturnBadJSON {
    fn from(re: ReturnError) -> ReturnBadJSON {
        ReturnBadJSON::new(re, None)
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
    pub fn new<S>(status: ReturnStatus, msg: S) -> Self
    where
        S: Into<String>,
    {
        ReturnError {
            status,
            msg: msg.into(),
        }
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
pub enum Severity {
    /// Sequoia's standard policy rejects this cert, even when allowing for
    /// SHA1 hashes.
    ///
    /// This probably means the cert is using very old, broken crypto.
    ///
    /// The cert should be replaced with a new one.
    Unusable,

    /// Sequoia's standard policy rejects this cert, but allows it when SHA1
    /// is allowed.
    ///
    /// This means the cert can be "fixed" by replacing the SHA1 hashes.
    /// (E.g. using https://gitlab.com/sequoia-pgp/keyring-linter)
    UsesSha1,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ReturnStatus {
    /// A private OpenPGP Key was provided - this is not allowed
    PrivateKey,

    /// The provided OpenPGP Key exceeds the allowed size limit
    KeySizeLimit,

    /// The cert failed a policy check, it cannot be used as is
    /// (this probably means the key is using very old, broken crypto).
    ///
    /// The "severity" field indicates how to explain the problem to the user
    /// (some keys can be repaired, other keys must be discarded).
    ///
    /// The "url" may be used to point users to a more verbose explanation
    /// of the problem, including suggestions for how to proceed.
    Policy { severity: Severity, url: String },

    /// General problem with the user-provided OpenPGP Cert/Keyring
    BadCert,

    /// Problem with a provided email address
    BadEmail,

    /// The OpenPGP key does not include a user_id that corresponds to an
    /// email address that was provided in "Certificate".
    ///
    /// This probably means that the user provided an OpenPGP key that is
    /// not suitable for use in this service.
    KeyMissingLocalUserId,

    /// requested entity couldn't be found (e.g. lookup by fingerprint)
    NotFound,

    /// A problem occurred that wasn't caused by external data.
    ///
    /// This should not happen - if it happens, it should probably be
    /// handled similar to HTTP 500, and investigated.
    InternalError,
}
