// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use rocket::response::status::BadRequest;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

use crate::models;
use crate::restd::cert_info::CertInfo;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum CertResultJSON {
    Good(ReturnGoodJSON),
    Bad(ReturnBadJSON),
}

impl From<Result<ReturnGoodJSON, ReturnBadJSON>> for CertResultJSON {
    fn from(res: Result<ReturnGoodJSON, ReturnBadJSON>) -> Self {
        match res {
            Ok(rgj) => CertResultJSON::Good(rgj),
            Err(rbj) => CertResultJSON::Bad(rbj),
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,

    /// hint for the UI, shows if the Cert should/can/cannot be uploaded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<Upload>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Action {
    /// This cert can be imported, it is "new" to this CA:
    /// We don't have a cert with this fingerprint yet.
    New,

    /// This cert can be imported as an update (we already have a cert
    /// with this fingerprint).
    ///
    /// The existing and new version of the cert will be merged.
    Update,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Upload {
    /// The UI recommends uploading this cert
    ///
    /// This will happen e.g. for:
    ///
    /// - Upload of updates for existing certs will be recommended.
    ///
    /// - Upload of revoked certs will be recommended, even if we don't
    /// have a cert with this fingerprint yet.
    Recommended,

    /// The UI should instruct the user to double-check this cert and
    /// explicitly confirm that it should be uploaded (and thus certified
    /// by the CA).
    Possible,

    /// This Cert cannot be uploaded
    Impossible,
}

/// A container for information about a "bad" Cert.
#[derive(Serialize, Deserialize)]
pub struct ReturnBadJSON {
    pub error: Vec<CertError>, // FIXME: read/write access methods?
    cert_info: Option<CertInfo>,
    upload: Upload,
}

impl ReturnBadJSON {
    pub fn new(error: CertError, cert_info: Option<CertInfo>) -> Self {
        Self {
            error: vec![error],
            cert_info,
            upload: Upload::Impossible,
        }
    }
}

impl From<CertError> for ReturnBadJSON {
    fn from(error: CertError) -> ReturnBadJSON {
        ReturnBadJSON::new(error, None)
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

/// A ReturnError is returned when a request fails before OpenPGP CA RESTD
/// identifies individual Certs.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnError {
    /// This status code should be mapped to a message that is shown to end
    /// users.
    pub status: ReturnStatus,

    /// this field is intended for debugging purposes only, it should
    /// probably not be displayed to end-users.
    pub msg: String,
}

impl From<ReturnError> for BadRequest<Json<ReturnError>> {
    fn from(re: ReturnError) -> Self {
        BadRequest(Some(Json(re)))
    }
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
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ReturnStatus {
    InternalError,
    NotFound,
}

/// A ReturnError is attached to a specific Cert (via ReturnBadJSON).
#[derive(Debug, Serialize, Deserialize)]
pub struct CertError {
    /// This status code should be mapped to a message that is shown to end
    /// users.
    pub status: CertStatus,

    /// this field is intended for debugging purposes only, it should
    /// probably not be displayed to end-users.
    pub msg: String,

    /// If set, this URL can be offered to users for more information about
    /// the Error that occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl CertError {
    pub fn new<S>(status: CertStatus, msg: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            status,
            msg: msg.into(),
            url: None,
        }
    }

    pub fn new_with_url<S>(status: CertStatus, url: String, msg: S) -> Self
    where
        S: Into<String>,
    {
        CertError {
            status,
            msg: msg.into(),
            url: Some(url),
        }
    }

    pub fn bad_req_ci(
        status: CertStatus,
        msg: String,
        ci: Option<CertInfo>,
    ) -> BadRequest<Json<ReturnBadJSON>> {
        let re = CertError::new(status, msg);
        let rbj = ReturnBadJSON::new(re, ci);
        BadRequest(Some(Json(rbj)))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum CertStatus {
    /// A private OpenPGP Key was provided - this is not allowed
    PrivateKey,

    /// The provided OpenPGP Cert exceeds the allowed size limit
    CertSizeLimit,

    /// The cert failed a policy check, it cannot be used
    /// (this probably means the key is using very old, broken crypto).
    ///
    /// [Sequoia's standard policy rejects this cert, even when allowing for
    /// SHA1 hashes]
    ///
    /// The "url" may be used to point users to a more verbose explanation
    /// of the problem, including suggestions for how to proceed.
    BadCert,

    /// Problem with an email address in a User ID
    BadUserID,

    /// The OpenPGP key does not include a user_id that corresponds to an
    /// email address that was provided in "Certificate".
    ///
    /// This probably means that the user provided an OpenPGP key that is
    /// not suitable for use in this service.
    CertMissingLocalUserId,

    /// A problem occurred that wasn't caused by external data.
    ///
    /// This should not happen - if it happens, it should probably be
    /// handled similar to HTTP 500, and investigated.
    InternalError,
}
