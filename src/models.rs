// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// OpenPGP CA is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPGP CA is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPGP CA.  If not, see <https://www.gnu.org/licenses/>.

use super::schema::*;

#[derive(Queryable, Debug, Clone, AsChangeset, Identifiable)]
pub struct Ca {
    pub id: i32,
    pub domainname: String,
}

#[derive(Insertable, Debug)]
#[table_name = "cas"]
pub struct NewCa<'a> {
    pub domainname: &'a str,
}

#[derive(Queryable, Debug, Associations, Clone, AsChangeset, Identifiable)]
#[belongs_to(Ca)]
pub struct Cacert {
    pub id: i32,
    pub cert: String,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub ca_id: i32,
}

#[derive(Insertable)]
#[table_name = "cacerts"]
pub struct NewCacert {
    pub cert: String,
    pub ca_id: i32,
}

#[derive(
    Identifiable,
    Queryable,
    Debug,
    Associations,
    Clone,
    AsChangeset,
    PartialEq,
    Eq,
    Hash,
)]
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

#[derive(
    Identifiable,
    Queryable,
    Debug,
    Associations,
    Clone,
    AsChangeset,
    PartialEq,
    Eq,
    Hash,
)]
pub struct Cert {
    pub id: i32,
    pub fingerprint: String,
    pub pub_cert: String,
}

#[derive(Insertable, Debug)]
#[table_name = "certs"]
pub struct NewCert<'a> {
    pub fingerprint: &'a str,
    pub pub_cert: &'a str,
}

#[derive(Identifiable, Queryable, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email {
    pub id: i32,
    pub addr: String,
}

#[derive(Insertable, Debug)]
#[table_name = "emails"]
pub struct NewEmail<'a> {
    pub addr: &'a str,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(Cert)]
#[belongs_to(Email)]
#[table_name = "certs_emails"]
pub struct CertEmail {
    pub id: i32,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub cert_id: i32,
    pub email_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "certs_emails"]
pub struct NewCertEmail {
    pub cert_id: i32,
    pub email_id: i32,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(User)]
#[belongs_to(Cert)]
#[table_name = "users_certs"]
pub struct UserCert {
    pub id: i32,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub cert_id: i32,
    pub user_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "users_certs"]
pub struct NewUserCert {
    pub cert_id: i32,
    pub user_id: i32,
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
    pub pub_key: String,
    pub cas_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "bridges"]
pub struct NewBridge<'a> {
    pub email: &'a str,
    pub scope: &'a str,
    pub pub_key: &'a str,
    pub cas_id: i32,
}

// FIXME: prefs table
