// Copyright 2019 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP-CA.
//
// OpenPGP-CA is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPGP-CA is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPGP-CA.  If not, see <https://www.gnu.org/licenses/>.

use std::env;
use failure::{self, ResultExt};
use diesel::prelude::*;
use diesel::r2d2;

use crate::schema::cas;
use crate::schema::users;
use crate::schema::emails;
use crate::models;
use crate::models::{Ca, User, Email};

pub type Result<T> = ::std::result::Result<T, failure::Error>;

// FIXME: or keep a Connection as lazy_static? or just make new Connections?!
fn get_conn() -> Result<r2d2::PooledConnection<r2d2::ConnectionManager
<SqliteConnection>>> {
    // bulk insert doesn't currently work with sqlite and r2d2:
    // https://github.com/diesel-rs/diesel/issues/1822

    // load config from .env
    dotenv::dotenv().ok();

    // setup DB
    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL must be set")?;

    let manager =
        r2d2::ConnectionManager::<SqliteConnection>::new(database_url);

    let pool = r2d2::Pool::builder()
        .build(manager)
        .unwrap();

    // --

    let conn = pool.get()?;

    // FIXME: handle/return error?!
    let _enable_foreign_key_constraints =
        diesel::sql_query("PRAGMA foreign_keys=1;").execute(&conn);

    Ok(conn)
}

pub struct Db {
    conn: r2d2::PooledConnection<r2d2::ConnectionManager<SqliteConnection>>,
}

impl Db {
    pub fn new() -> Self {
        match get_conn() {
            Ok(conn) => Db { conn },
            _ => panic!("couldn't get database connection") // FIXME; ?!
        }
    }

    pub fn insert_ca(&self, ca: models::NewCa) -> Result<()> {
        diesel::insert_into(cas::table)
            .values(&ca)
            .execute(&self.conn)
            .context("Error saving new CA")?;

        Ok(())
    }

    pub fn update_ca(&self, ca: &models::Ca) -> Result<()> {
        diesel::update(cas::table)
            .set(ca)
            .execute(&self.conn)
            .context("Error updating CA")?;

        Ok(())
    }

    pub fn delete_ca(&self, name: &str) -> Result<()> {
        // FIXME: check if domain exists?

        diesel::delete(cas::dsl::cas.filter(cas::name.eq(name)))
            .execute(&self.conn)
            .context("Error deleting CA")?;

        Ok(())
    }

    pub fn search_ca(&self, name: &str) -> Result<Option<Ca>> {
        let res = cas::table.filter(cas::name.eq(name))
            .load::<Ca>(&self.conn)
            .context("Error loading ca")?;

        match res.len() {
            0 => Ok(None),
            1 => Ok(Some(res[0].clone())),
            _ => panic!("search_ca for {} found {} results, expected 1. \
            (Database constraints should make this impossible)",
                        name, res.len())
        }
    }

    pub fn list_cas(&self) -> Result<Vec<Ca>> {
        Ok(cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?)
    }

    pub fn check_ca_exists(&self, ca_name: &str) -> Result<bool> {
        Ok(self.search_ca(ca_name)?.is_some())
    }

    pub fn insert_user(&self, user: models::NewUser) -> Result<i32> {
        use diesel::result::Error;
        // there seems to be no nice way to get the ID of a newly inserted
        // row in sqlite:
        // https://github.com/diesel-rs/diesel/blob/master/examples/sqlite/all_about_inserts/src/lib.rs#L278

        // FIXME: https://sqlite.org/c3ref/last_insert_rowid.html
        let inserted_users: std::result::Result<Vec<User>, Error> =
            self.conn.transaction::<_, Error, _>(|| {
                let inserted_count = diesel::insert_into(users::table)
                    .values(&user)
                    .execute(&self.conn)?; // FIXME

                assert_eq!(inserted_count, 1, "insert_user: couldn't insert user");

                Ok(users::table
                    .order(users::id.desc())
                    .limit(inserted_count as i64)
                    .load(&self.conn)?
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>())
            });

        if let Ok(users) = inserted_users {
            Ok(users[0].id)
        } else {
            Err(failure::err_msg("insert_user() get inserted id failed"))
        }
    }

    pub fn list_users(&self) -> Result<Vec<User>> {
        Ok(users::table
            .load::<User>(&self.conn)
            .context("Error loading users")?)
    }

    pub fn get_emails(&self, user: User) -> Result<Vec<Email>> {
        Ok(Email::belonging_to(&user)
            .load::<Email>(&self.conn)
            .context("Error loading emails")?)
    }

    pub fn insert_email(&self, email: models::NewEmail) -> Result<()> {
        diesel::insert_into(emails::table)
            .values(&email)
            .execute(&self.conn)
            .context("Error saving new email")?;

        Ok(())
    }
}