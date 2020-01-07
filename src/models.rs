// Copyright 2019 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA.
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


#[derive(Queryable, Debug, Clone, AsChangeset)]
pub struct Ca {
    pub id: i32,
    pub domainname: String,
}

#[derive(Insertable, Debug)]
#[table_name = "cas"]
pub struct NewCa<'a> {
    pub domainname: &'a str,
}

#[derive(Queryable, Debug, Associations, Clone, AsChangeset)]
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

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
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

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(User)]
pub struct Usercert {
    pub id: i32,
    pub pub_cert: String,
    pub fingerprint: String,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub user_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "usercerts"]
pub struct NewUsercert<'a> {
    pub pub_cert: &'a str,
    pub fingerprint: &'a str,
    pub user_id: i32,
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
#[belongs_to(Usercert)]
#[belongs_to(Email)]
#[table_name = "certs_emails"]
pub struct CertEmail {
    pub id: i32,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub usercert_id: i32,
    pub email_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "certs_emails"]
pub struct NewCertEmail {
    pub usercert_id: i32,
    pub email_id: i32,
}

#[derive(Identifiable, Queryable, Debug, Associations, Clone, AsChangeset)]
#[belongs_to(Usercert)]
pub struct Revocation {
    pub id: i32,
    pub revocation: String,
    // FIXME - https://docs.diesel.rs/diesel/associations/index.html
    pub usercert_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "revocations"]
pub struct NewRevocation<'a> {
    pub revocation: &'a str,
    pub usercert_id: i32,
}

#[derive(Identifiable, Queryable, Clone, AsChangeset, Debug)]
pub struct Bridge {
    pub id: i32,
    pub name: String,
    pub pub_key: String,
    pub cas_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "bridges"]
pub struct NewBridge<'a> {
    pub name: &'a str,
    pub pub_key: &'a str,
    pub cas_id: i32,
}

// FIXME: prefs table