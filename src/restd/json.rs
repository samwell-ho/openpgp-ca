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

/// A container for return-data about one Cert.
///
/// This data structure binds together two different variants of result:
/// One if the Cert can be processed, and another if Cert cannot be processed.
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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

/// User-provided input data for OpenPGP CA RESTD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// email addresses that the organization associates with this user
    pub email: Vec<String>,

    /// the name that the organization associates with this user
    pub name: Option<String>,

    /// as input, cert may contain a keyring consisting of multiple certs.
    /// as output, this will always contain exactly one cert.
    pub cert: String,

    /// optional: store revocations for this cert.
    pub revocations: Vec<String>,

    /// must not be changed by input data (default for new certs: false),
    /// but will always be returned.
    pub delisted: Option<bool>,

    /// must not be changed by input data (default for new certs: false),
    /// but will always be returned.
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

/// A ReturnError gets returned when a request fails before OpenPGP CA RESTD
/// splits the input "Certificate" data into individual Certs.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnError {
    pub status: ReturnStatus,

    /// This field is intended for debugging purposes only, it should
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
    BadKeyring,
    NotFound,
    InternalError,
}

/// A CertError gives error information about one specific Cert.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertError {
    /// This status code should be mapped to a message that is shown to end
    /// users.
    pub status: CertStatus,

    /// this field is intended for debugging purposes only, it should
    /// probably not be displayed to end-users.
    pub msg: String,

    /// If set, this URL can be offered to users for more verbose information
    /// about the Error that occurred (if possible: including suggestions for
    /// how to proceed).
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

    pub fn new_with_url<S>(
        status: CertStatus,
        url: Option<String>,
        msg: S,
    ) -> Self
    where
        S: Into<String>,
    {
        CertError {
            status,
            msg: msg.into(),
            url,
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
    /// The cert failed a policy check, it cannot be used
    /// (this probably means the key is using very old, broken crypto).
    ///
    /// This means that Sequoia's standard policy rejects this cert.
    BadCert,

    /// The OpenPGP key does not include a user_id that corresponds to an
    /// email address that was provided in "Certificate".
    ///
    /// This probably means that the user provided an OpenPGP key that is
    /// not suitable for use in this service.
    CertMissingLocalUserId,

    /// A bad email address was provided in 'Certificate'
    BadEmail,

    /// The provided OpenPGP Cert exceeds the allowed size limit
    CertSizeLimit,

    /// A private OpenPGP Key was provided - this is not allowed
    PrivateKey,

    /// A problem occurred that wasn't caused by external data.
    ///
    /// This should not happen - if it happens, it should probably be
    /// handled similar to HTTP 500, and investigated.
    InternalError,
}
