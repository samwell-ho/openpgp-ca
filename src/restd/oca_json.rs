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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub email: Vec<String>,
    pub name: Option<String>,
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

/// A container for information about a Cert.
///
/// `cert_info` contains factual information about a cert.
///
/// Later we may add e.g. `cert_lints` (... ?)
#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnJSON {
    pub cert_info: CertInfo,

    // later:
    // - cert_lints (e.g. expiry warnings, deprecated crypto, ...)

    // action can be "new" or "update"
    pub action: Option<Action>,

    pub certificate: Certificate,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    New,
    Update,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReturnError {
    status: ReturnStatus,
    msg: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ReturnStatus {
    /// A private OpenPGP Key was provided - this is not allowed
    PrivateKey,

    /// The provided OpenPGP Key exceeds the allowed size limit
    KeySizeLimit,

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
