// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

// temporary workaround for https://github.com/rust-lang/rust-clippy/issues/9014 [2022-07-27]
#![allow(clippy::extra_unused_lifetimes)]

use crate::db::schema::*;

#[derive(Queryable, Debug, Clone, AsChangeset, Identifiable)]
pub struct Ca {
    pub id: i32,
    pub domainname: String,
    pub backend: Option<String>,
}

#[derive(Insertable, Debug)]
#[table_name = "cas"]
pub struct NewCa<'a> {
    pub domainname: &'a str,
    pub backend: Option<&'a str>, // backend configuration, if not softkey
}

#[derive(Queryable, Debug, Associations, Clone, AsChangeset, Identifiable)]
#[belongs_to(Ca)]
pub struct Cacert {
    pub id: i32,
    pub fingerprint: String,
    pub priv_cert: String, // bad name (priv key if softkey, pub key if card backed)
    // https://docs.diesel.rs/diesel/associations/index.html
    pub ca_id: i32,
}

#[derive(Insertable)]
#[table_name = "cacerts"]
pub struct NewCacert<'a> {
    pub fingerprint: &'a str,
    pub priv_cert: String,
    pub ca_id: i32,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset, PartialEq, Eq, Hash)]
#[belongs_to(Ca)]
pub struct User {
    pub id: i32,
    pub name: Option<String>,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub ca_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub name: Option<&'a str>,
    pub ca_id: i32,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset, PartialEq, Eq, Hash)]
#[belongs_to(User)]
pub struct Cert {
    pub id: i32,
    pub fingerprint: String,
    pub pub_cert: String,
    pub user_id: Option<i32>,
    pub delisted: bool,
    pub inactive: bool,
}

#[derive(Insertable, Debug)]
#[table_name = "certs"]
pub struct NewCert<'a> {
    pub fingerprint: &'a str,
    pub pub_cert: &'a str,
    pub user_id: Option<i32>,
    pub delisted: bool,
    pub inactive: bool,
}

#[derive(Associations, Identifiable, Queryable, Debug, Clone, AsChangeset)]
#[table_name = "certs_emails"]
#[belongs_to(Cert)]
pub struct CertEmail {
    pub id: i32,
    pub addr: String,
    pub cert_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "certs_emails"]
pub struct NewCertEmail {
    pub addr: String,
    pub cert_id: i32,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(Cert)]
pub struct Revocation {
    pub id: i32,
    pub hash: String,
    pub revocation: String,
    pub published: bool,
    // FIXME - https://docs.diesel.rs/diesel/associations/index.html
    pub cert_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "revocations"]
pub struct NewRevocation<'a> {
    pub hash: &'a str,
    pub revocation: &'a str,
    pub published: bool,
    pub cert_id: i32,
}

#[derive(Identifiable, Queryable, Clone, AsChangeset, Debug)]
pub struct Bridge {
    pub id: i32,
    pub email: String,
    pub scope: String,
    pub cert_id: i32,
    pub cas_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "bridges"]
pub struct NewBridge<'a> {
    pub email: &'a str,
    pub scope: &'a str,
    pub cert_id: i32,
    pub cas_id: i32,
}

// FIXME: prefs table
