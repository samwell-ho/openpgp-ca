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

use super::schema::cas;
use super::schema::users;
use super::schema::emails;
use super::schema::bridges;


#[derive(Queryable, Debug, Clone, AsChangeset)]
pub struct Ca {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub ca_key: String,
    pub revoc_cert: String,
}

#[derive(Insertable)]
#[table_name = "cas"]
pub struct NewCa<'a> {
    pub name: &'a str,
    pub email: String,
    pub ca_key: &'a str,
    pub revoc_cert: &'a str,
}


#[derive(Identifiable, Queryable, Debug)]
pub struct User {
    pub id: i32,
    pub name: Option<String>,
    pub pub_key: String,
    pub revoc_cert: Option<String>,
    // https://docs.diesel.rs/diesel/associations/index.html
    pub cas_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub name: Option<&'a str>,
    pub pub_key: &'a str,
    pub revoc_cert: Option<&'a str>,
    pub cas_id: i32,
}


#[derive(Identifiable, Queryable, Associations, Debug)]
#[belongs_to(User)]
pub struct Email {
    pub id: i32,
    pub addr: String,
    pub user_id: i32,
}

#[derive(Insertable, Debug)]
#[table_name = "emails"]
pub struct NewEmail<'a> {
    pub addr: &'a str,
    pub user_id: i32,
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