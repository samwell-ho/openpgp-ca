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
        diesel::update(cas::table)
            .set(ca)
            .execute(&self.conn)
            .context("Error updating CA")?;

        Ok(())
    }

    pub fn update_cacert(&self, cacert: &Cacert) -> Result<()> {
        diesel::update(cacerts::table)
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

    pub fn new_usercert(&self, name: Option<&str>, pub_cert: &str,
                        fingerprint: &str, emails: &[&str],
                        revocs: &Vec<String>, ca_cert_tsigned: Option<&str>,
                        updates_cert_id: Option<i32>) -> Result<()> {
        self.conn.transaction::<_, failure::Error, _>(|| {
            let (ca, mut ca_cert_db) = self.get_ca()
                .context("Couldn't find CA")?.unwrap();

            // store updated CA cert, if applicable
            // FIXME: fn parameter should be just the new tsig?
            if let Some(ca_cert) = ca_cert_tsigned {
                ca_cert_db.cert = ca_cert.to_string();
                self.update_cacert(&ca_cert_db)?;
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
                    NewRevocation { revocation, usercert_id: c.id })?;
            }

            // Emails
            for addr in emails {
                self.insert_or_link_email(addr, c.id)?;
            }
            Ok(())
        })
    }


    pub fn add_usercert(&self, newcert: NewUsercert, emails: &[String])
                        -> Result<()> {
        self.conn.transaction::<_, failure::Error, _>(|| {
            // UserCert
            let c = self.insert_usercert(newcert)?;

            // Emails
            for addr in emails {
                self.insert_or_link_email(addr, c.id)?;
            }

            Ok(())
        })
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
        let e: Vec<Email> = emails::table.filter(emails::addr.eq(email))
            .load::<Email>(&self.conn)
            .context("Error loading email")?;

        let e =
            match e.len() {
                0 => return Err(failure::err_msg("Email address not found")),
                1 => &e[0],
                _ => panic!("searching for email {} found {} results,\
             expected 0 or 1. \
            (Database constraints should make this impossible)",
                            email, e.len())
            };

        let cert_email = CertEmail::belonging_to(e).load::<CertEmail>(&self.conn)
            .expect("Error loading posts");

        let mut certs: Vec<Usercert> = Vec::new();
        for ce in cert_email {
            let mut c = usercerts::table
                .filter(usercerts::id.eq(ce.usercert_id))
                .load::<Usercert>(&self.conn)
                .context("Error loading Cert")?;

            certs.append(&mut c);
        }

        Ok(certs)
    }

    pub fn list_usercerts(&self) -> Result<Vec<Usercert>> {
        Ok(usercerts::table
            .load::<Usercert>(&self.conn)
            .context("Error loading usercerts")?)
    }

    pub fn get_revocations(&self, cert: &Usercert)
                           -> Result<Vec<Revocation>> {
        let res = Revocation::belonging_to(cert).load::<Revocation>(&self.conn);

        // FIXME handle errors?!

        Ok(res?)
    }

    pub fn add_revocation(&self, revocation: &str, cert: &Usercert)
                          -> Result<Revocation> {
        self.insert_revocation(NewRevocation {
            revocation,
            usercert_id: cert.id,
        })
    }

    pub fn get_emails_by_usercert(&self, cert: &Usercert)
                                  -> Result<Vec<Email>> {
        let mut emails = Vec::new();

        let ces: Vec<CertEmail> = certs_emails::table
            .filter(certs_emails::usercert_id.eq(cert.id))
            .load::<CertEmail>(&self.conn)
            .context("Error loading CertEmails")?;

        for ce in ces {
            let mut e = emails::table
                .filter(emails::id.eq(ce.email_id))
                .load::<Email>(&self.conn)
                .context("Error loading Email")?;

            emails.append(&mut e);
        }

        Ok(emails)
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
        diesel::update(bridges::table)
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