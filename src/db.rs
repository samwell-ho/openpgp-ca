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

use failure::{self, ResultExt};
use diesel::prelude::*;
use diesel::r2d2::{Pool, PooledConnection, ConnectionManager};

use crate::schema::*;
use crate::models::*;
use crate::pgp::Pgp;

pub type Result<T> = ::std::result::Result<T, failure::Error>;


// FIXME: or keep a Connection as lazy_static? or just make new Connections?!
fn get_conn(database: Option<String>)
            -> Result<PooledConnection<ConnectionManager<SqliteConnection>>> {

    // bulk insert doesn't currently work with sqlite and r2d2:
    // https://github.com/diesel-rs/diesel/issues/1822

    // setup DB
    let database_url = database.expect("no database has been set");

    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder().build(manager).unwrap();

    // --

    let conn = pool.get()?;

    // enable handling of foreign key constraints in sqlite
    let enable_foreign_key_constraints =
        diesel::sql_query("PRAGMA foreign_keys=1;").execute(&conn);

    // throw error if foreign keys are not supported
    if enable_foreign_key_constraints.is_err() {
        panic!("Couldn't set 'PRAGMA foreign_keys=1;'");
    }

    Ok(conn)
}

pub struct Db {
    conn: PooledConnection<ConnectionManager<SqliteConnection>>,
}

impl Db {
    pub fn new(database: Option<String>) -> Self {
        match get_conn(database) {
            Ok(conn) => Db { conn },
            _ => panic!("couldn't get database connection")
        }
    }

    pub fn get_conn(&self)
                    -> &PooledConnection<ConnectionManager<SqliteConnection>> {
        &self.conn
    }

    // --- building block functions ---

    fn insert_usercert(&self, cert: NewUsercert) -> Result<Usercert> {
        let inserted_count = diesel::insert_into(usercerts::table)
            .values(&cert)
            .execute(&self.conn)?;

        assert_eq!(inserted_count, 1, "insert_usercert: couldn't insert usercert");

        let c: Vec<Usercert> = usercerts::table
            .order(usercerts::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        assert_eq!(c.len(), 1);

        Ok(c[0].clone())
    }

    fn insert_revocation(&self, revoc: NewRevocation)
                         -> Result<Revocation> {
        let inserted_count = diesel::insert_into(revocations::table)
            .values(&revoc)
            .execute(&self.conn)?;

        assert_eq!(inserted_count, 1, "insert_revocation: couldn't insert revocation");

        let r: Vec<Revocation> = revocations::table
            .order(revocations::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        assert_eq!(r.len(), 1);

        Ok(r[0].clone())
    }

    fn insert_or_link_email(&self, addr: &str, usercert_id: i32) -> Result<Email> {
        if let Some(e) = self.get_email(addr)? {
            let ce = NewCertEmail { usercert_id, email_id: e.id };
            let inserted_count = diesel::insert_into(certs_emails::table)
                .values(&ce)
                .execute(&self.conn)
                .context("Error saving new certs_emails")?;

            assert_eq!(inserted_count, 1, "insert_email: couldn't insert certs_emails");

            Ok(e)
        } else {
            self.insert_email(NewEmail { addr }, usercert_id)
        }
    }


    fn get_email(&self, addr: &str) -> Result<Option<Email>> {
        let emails: Vec<Email> = emails::table
            .filter(emails::addr.eq(addr))
            .load::<Email>(&self.conn)
            .context("Error loading Emails")?;

        match emails.len() {
            0 => Ok(None),
            1 => Ok(Some(emails[0].clone())),
            _ => Err(failure::err_msg("found more than one email for addr, \
            this should not happen"))
        }
    }

    fn insert_email(&self, email: NewEmail, usercert_id: i32) -> Result<Email> {
        let inserted_count = diesel::insert_into(emails::table)
            .values(&email)
            .execute(&self.conn)
            .context("Error saving new email")?;

        assert_eq!(inserted_count, 1, "insert_email: couldn't insert email");

        let e: Vec<Email> = emails::table
            .order(emails::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        assert_eq!(e.len(), 1);

        let e = e[0].clone();

        let ce = NewCertEmail { usercert_id, email_id: e.id };
        let inserted_count = diesel::insert_into(certs_emails::table)
            .values(&ce)
            .execute(&self.conn)
            .context("Error saving new certs_emails")?;

        assert_eq!(inserted_count, 1, "insert_email: couldn't insert certs_emails");

        Ok(e)
    }

    // --- public ---

    pub fn insert_ca(&self, ca: NewCa, ca_key: &str) -> Result<()> {
        assert!(Pgp::armored_to_cert(ca_key).is_ok());

        self.conn.transaction::<_, failure::Error, _>(|| {
            diesel::insert_into(cas::table)
                .values(&ca)
                .execute(&self.conn)
                .context("Error saving new CA")?;

            let cas = cas::table
                .load::<Ca>(&self.conn)
                .context("Error loading CAs")?;

            let ca = cas.first().unwrap();

            let ca_cert = NewCacert { ca_id: ca.id, cert: ca_key.to_string() };
            diesel::insert_into(cacerts::table)
                .values(&ca_cert)
                .execute(&self.conn)
                .context("Error saving new CA Cert")?;

            Ok(())
        })
    }

    pub fn update_ca(&self, ca: &Ca) -> Result<()> {
        diesel::update(ca)
            .set(ca)
            .execute(&self.conn)
            .context("Error updating CA")?;

        Ok(())
    }

    pub fn update_cacert(&self, cacert: &Cacert) -> Result<()> {
        assert!(Pgp::armored_to_cert(&cacert.cert).is_ok());

        diesel::update(cacert)
            .set(cacert)
            .execute(&self.conn)
            .context("Error updating CaCert")?;

        Ok(())
    }


    pub fn get_ca(&self) -> Result<Option<(Ca, Cacert)>> {
        let cas = cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?;


        match cas.len() {
            0 => Ok(None),
            1 => {
                let ca = cas[0].clone();

                let ca_certs: Vec<_> = cacerts::table
                    .filter(cacerts::ca_id.eq(ca.id))
                    .load::<Cacert>(&self.conn)
                    .context("Error loading CA Certs")?;

                // FIXME: which cert(s) should be returned?
                // -> there can be more than one "active" cert,
                // as well as even more "inactive" certs.
                assert_eq!(ca_certs.len(), 1);
                let ca_cert: Cacert = ca_certs[0].clone();

                Ok(Some((ca, ca_cert)))
            }
            _ => panic!("found more than 1 CA in database. this should \
            never happen")
        }
    }

    pub fn add_usercert(&self, name: Option<&str>, pub_cert: &str,
                        fingerprint: &str, emails: &[&str],
                        revocs: &Vec<String>, ca_cert_tsigned: Option<&str>,
                        updates_cert_id: Option<i32>) -> Result<Usercert> {
        self.conn.transaction::<_, failure::Error, _>(|| {
            let (ca, mut cacert_db) = self.get_ca()
                .context("Couldn't find CA")?.unwrap();

            // merge updated tsigned CA cert, if applicable
            if let Some(ca_cert_tsigned) = ca_cert_tsigned {
                let tsigned = Pgp::armored_to_cert(&ca_cert_tsigned)?;

                let merged = Pgp::armored_to_cert(&cacert_db.cert)?
                    .merge(tsigned)?;
                cacert_db.cert = Pgp::priv_cert_to_armored(&merged)?;
                self.update_cacert(&cacert_db)?;
            }

            // UserCert
            let newcert = NewUsercert {
                updates_cert_id,
                pub_cert,
                name,
                fingerprint,
                ca_id: ca.id,
            };
            let c = self.insert_usercert(newcert)?;

            // Revocations
            for revocation in revocs {
                self.insert_revocation(
                    NewRevocation {
                        revocation,
                        usercert_id: c.id,
                        published: false,
                    })?;
            }

            // Emails
            for addr in emails {
                self.insert_or_link_email(addr, c.id)?;
            }
            Ok(c)
        })
    }

    pub fn update_usercert(&self, usercert: &Usercert) -> Result<()> {
        diesel::update(usercert)
            .set(usercert)
            .execute(&self.conn)
            .context("Error updating Usercert")?;

        Ok(())
    }

    pub fn update_revocation(&self, revocation: &Revocation) -> Result<()> {
        diesel::update(revocation)
            .set(revocation)
            .execute(&self.conn)
            .context("Error updating Revocation")?;

        Ok(())
    }

    pub fn get_usercert_by_id(&self, id: i32) -> Result<Option<Usercert>> {
        let db: Vec<Usercert> = usercerts::table
            .filter(usercerts::id.eq(id))
            .load::<Usercert>(&self.conn)
            .context("Error loading UserCert by id")?;

        if let Some(usercert) = db.get(0) {
            Ok(Some(usercert.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn get_usercert(&self, fingerprint: &str)
                        -> Result<Option<Usercert>> {
        let u = usercerts::table
            .filter(usercerts::fingerprint.eq(fingerprint))
            .load::<Usercert>(&self.conn)
            .context("Error loading UserCert by fingerprint")?;

        assert!(u.len() <= 1);
        if u.is_empty() {
            Ok(None)
        } else {
            Ok(Some(u[0].clone()))
        }
    }

    pub fn get_usercerts(&self, email: &str) -> Result<Vec<Usercert>> {
        if let Some(email) = self.get_email(email)? {
            let cert_ids = CertEmail::belonging_to(&email)
                .select(certs_emails::usercert_id);

            Ok(usercerts::table
                .filter(usercerts::id.eq_any(cert_ids))
                .load::<Usercert>(&self.conn)
                .expect("could not load usercerts"))
        } else {
            // FIXME: or error for email not found?
            Ok(vec![])
        }
    }

    pub fn list_usercerts(&self) -> Result<Vec<Usercert>> {
        Ok(usercerts::table
            .load::<Usercert>(&self.conn)
            .context("Error loading usercerts")?)
    }

    pub fn get_revocations(&self, cert: &Usercert)
                           -> Result<Vec<Revocation>> {
        Ok(Revocation::belonging_to(cert).load::<Revocation>(&self.conn)?)
    }

    pub fn add_revocation(&self, revocation: &str, cert: &Usercert)
                          -> Result<Revocation> {
        self.insert_revocation(
            NewRevocation {
                revocation,
                usercert_id: cert.id,
                published: false,
            })
    }

    pub fn get_revocation_by_id(&self, id: i32) -> Result<Option<Revocation>> {
        let db: Vec<Revocation> = revocations::table
            .filter(revocations::id.eq(id))
            .load::<Revocation>(&self.conn)
            .context("Error loading Revocation by id")?;

        if let Some(revocation) = db.get(0) {
            Ok(Some(revocation.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn get_emails_by_usercert(&self, cert: &Usercert)
                                  -> Result<Vec<Email>> {
        let email_ids = CertEmail::belonging_to(cert)
            .select(certs_emails::email_id);

        Ok(emails::table
            .filter(emails::id.eq_any(email_ids))
            .load::<Email>(&self.conn)
            .expect("could not load emails"))
    }

    pub fn insert_bridge(&self, bridge: NewBridge) -> Result<Bridge> {
        let inserted_count = diesel::insert_into(bridges::table)
            .values(&bridge)
            .execute(&self.conn)
            .context("Error saving new bridge")?;


        assert_eq!(inserted_count, 1, "insert_user: couldn't insert bridge");

        let b: Vec<Bridge> = bridges::table
            .order(bridges::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        assert_eq!(b.len(), 1);

        Ok(b[0].clone())
    }

    pub fn update_bridge(&self, bridge: &Bridge) -> Result<()> {
        diesel::update(bridge)
            .set(bridge)
            .execute(&self.conn)
            .context("Error updating Bridge")?;

        Ok(())
    }

    pub fn search_bridge(&self, email: &str) -> Result<Option<Bridge>> {
        let res = bridges::table.filter(bridges::email.eq(email))
            .load::<Bridge>(&self.conn)
            .context("Error loading bridge")?;

        match res.len() {
            0 => Ok(None),
            1 => Ok(Some(res[0].clone())),
            _ => panic!("search_bridge for {} found {} results, expected 1. \
            (Database constraints should make this impossible)",
                        email, res.len())
        }
    }

    pub fn list_bridges(&self) -> Result<Vec<Bridge>> {
        Ok(bridges::table
            .load::<Bridge>(&self.conn)
            .context("Error loading bridges")?)
    }

    pub fn migrations(&self) {
        embed_migrations!();

        embedded_migrations::run(&self.conn).unwrap_or_else(|e| {
            panic!("failed to configure database, error {}", e);
        });
    }
}