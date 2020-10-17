// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use diesel::prelude::*;

use anyhow::{Context, Result};

use crate::models::*;
use crate::pgp::Pgp;
use crate::schema::*;

pub struct Db {
    conn: SqliteConnection,
}

impl Db {
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        match db_url {
            None => Err(anyhow::anyhow!("no database has been set")),
            Some(db_url) => {
                let conn = SqliteConnection::establish(&db_url)
                    .context(format!("Error connecting to {}", db_url))?;

                // enable handling of foreign key constraints in sqlite
                diesel::sql_query("PRAGMA foreign_keys=1;")
                    .execute(&conn)
                    .context("Couldn't set 'PRAGMA foreign_keys=1;'")?;

                Ok(Db { conn })
            }
        }
    }

    pub fn get_conn(&self) -> &SqliteConnection {
        &self.conn
    }

    // --- building block functions ---

    fn insert_user(&self, user: NewUser) -> Result<User> {
        let inserted_count = diesel::insert_into(users::table)
            .values(&user)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_user: insert should return count '1'"
            ));
        }

        let u: Vec<User> = users::table
            .order(users::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if u.len() == 1 {
            Ok(u[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_user: unexpected insert failure"))
        }
    }

    fn insert_cert(&self, cert: NewCert) -> Result<Cert> {
        let inserted_count = diesel::insert_into(certs::table)
            .values(&cert)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_cert: insert should return count '1'"
            ));
        }

        let c: Vec<Cert> = certs::table
            .order(certs::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if c.len() == 1 {
            Ok(c[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_cert: unexpected insert failure"))
        }
    }

    fn insert_revocation(&self, revoc: NewRevocation) -> Result<Revocation> {
        let inserted_count = diesel::insert_into(revocations::table)
            .values(&revoc)
            .execute(&self.conn)?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_revocation: insert should return count '1'"
            ));
        }

        let r: Vec<Revocation> = revocations::table
            .order(revocations::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if r.len() == 1 {
            Ok(r[0].clone())
        } else {
            Err(anyhow::anyhow!(
                "insert_revocation: unexpected insert failure"
            ))
        }
    }

    fn insert_email(&self, email: NewCertEmail) -> Result<CertEmail> {
        let inserted_count = diesel::insert_into(certs_emails::table)
            .values(&email)
            .execute(&self.conn)
            .context("Error saving new email")?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_email: insert should return count '1'"
            ));
        }

        let e: Vec<CertEmail> = certs_emails::table
            .order(certs_emails::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .collect();

        if e.len() != 1 {
            return Err(anyhow::anyhow!(
                "insert_email: unexpected insert failure [emails]"
            ));
        }

        Ok(e[0].clone())
    }

    // --- public ---

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

                match ca_certs.len() {
                    0 => Ok(None),
                    1 => Ok(Some((ca, ca_certs[0].to_owned()))),
                    _ => {
                        // FIXME: which cert(s) should be returned?
                        // -> there can be more than one "active" cert,
                        // as well as even more "inactive" certs.
                        unimplemented!("get_ca: more than one ca_cert in DB");
                    }
                }
            }
            _ => Err(anyhow::anyhow!(
                "more than 1 CA in database. this should never happen"
            )),
        }
    }

    pub fn insert_ca(
        &self,
        ca: NewCa,
        ca_key: &str,
        fingerprint: &str,
    ) -> Result<()> {
        diesel::insert_into(cas::table)
            .values(&ca)
            .execute(&self.conn)
            .context("Error saving new CA")?;

        let cas = cas::table
            .load::<Ca>(&self.conn)
            .context("Error loading CAs")?;

        let ca = cas.first().unwrap();

        let ca_cert = NewCacert {
            fingerprint,
            ca_id: ca.id,
            priv_cert: ca_key.to_string(),
        };
        diesel::insert_into(cacerts::table)
            .values(&ca_cert)
            .execute(&self.conn)
            .context("Error saving new CA Cert")?;

        Ok(())
    }

    pub fn update_cacert(&self, cacert: &Cacert) -> Result<()> {
        diesel::update(cacert)
            .set(cacert)
            .execute(&self.conn)
            .context("Error updating CaCert")?;

        Ok(())
    }

    pub fn get_users_sort_by_name(&self) -> Result<Vec<User>> {
        Ok(users::table
            .order((users::name, users::id))
            .load::<User>(&self.conn)
            .context("Error loading users")?)
    }

    pub fn get_user_by_cert(&self, cert: &Cert) -> Result<Option<User>> {
        match cert.user_id {
            None => Ok(None),
            Some(search_id) => {
                let users = users::table
                    .filter(users::id.eq(search_id))
                    .load::<User>(&self.conn)?;

                match users.len() {
                    0 => Ok(None),
                    1 => Ok(Some(users[0].clone())),
                    _ => Err(anyhow::anyhow!(
                        "get_user_by_cert: found more than 1 user for a cert. this should be impossible."
                    )),
                }
            }
        }
    }

    pub fn add_user(
        &self,
        name: Option<&str>,
        (pub_cert, fingerprint): (&str, &str),
        emails: &[&str],
        revocation_certs: &[String],
        ca_cert_tsigned: Option<&str>,
    ) -> Result<User> {
        let (ca, mut cacert_db) =
            self.get_ca().context("Couldn't find CA")?.unwrap();

        // merge new trust signature into local CA cert (if applicable)
        if let Some(ca_cert_tsigned) = ca_cert_tsigned {
            let tsigned = Pgp::armored_to_cert(&ca_cert_tsigned)?;

            let merged =
                Pgp::armored_to_cert(&cacert_db.priv_cert)?.merge(tsigned)?;
            cacert_db.priv_cert = Pgp::priv_cert_to_armored(&merged)?;

            // update new version of CA cert in database
            self.update_cacert(&cacert_db)?;
        }

        // User
        let newuser = NewUser { name, ca_id: ca.id };
        let user = self.insert_user(newuser)?;

        let cert = self.add_cert(pub_cert, fingerprint, Some(user.id))?;

        // Revocations
        for revocation in revocation_certs {
            let hash = &Pgp::revocation_to_hash(revocation)?;
            self.insert_revocation(NewRevocation {
                hash,
                revocation,
                cert_id: cert.id,
                published: false,
            })?;
        }

        // Emails
        for &addr in emails {
            self.insert_email(NewCertEmail {
                addr: addr.to_owned(),
                cert_id: cert.id,
            })?;
        }
        Ok(user)
    }

    pub fn update_user(&self, user: &User) -> Result<()> {
        diesel::update(user)
            .set(user)
            .execute(&self.conn)
            .context("Error updating User")?;

        Ok(())
    }

    pub fn add_cert(
        &self,
        pub_cert: &str,
        fingerprint: &str,
        user_id: Option<i32>,
    ) -> Result<Cert> {
        let newcert = NewCert {
            pub_cert,
            fingerprint,
            delisted: false,
            inactive: false,
            user_id,
        };
        self.insert_cert(newcert)
    }

    pub fn update_cert(&self, cert: &Cert) -> Result<()> {
        diesel::update(cert)
            .set(cert)
            .execute(&self.conn)
            .context("Error updating Cert")?;

        Ok(())
    }

    pub fn get_cert_by_id(&self, id: i32) -> Result<Option<Cert>> {
        let db: Vec<Cert> = certs::table
            .filter(certs::id.eq(id))
            .load::<Cert>(&self.conn)
            .context("Error loading Cert by id")?;

        if let Some(cert) = db.get(0) {
            Ok(Some(cert.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn get_cert(&self, fingerprint: &str) -> Result<Option<Cert>> {
        let c = certs::table
            .filter(certs::fingerprint.eq(fingerprint))
            .load::<Cert>(&self.conn)
            .context("Error loading Cert by fingerprint")?;

        match c.len() {
            0 => Ok(None),
            1 => Ok(Some(c[0].clone())),
            _ => Err(anyhow::anyhow!("get_cert: expected 0 or 1 cert")),
        }
    }

    pub fn get_certs_by_email(&self, email: &str) -> Result<Vec<Cert>> {
        let cert_ids = certs_emails::table
            .filter(certs_emails::addr.eq(email))
            .select(certs_emails::cert_id);

        Ok(certs::table
            .filter(certs::id.eq_any(cert_ids))
            .load::<Cert>(&self.conn)
            .expect("could not load certs"))
    }

    /// All Certs that belong to `user`, ordered by certs::id
    pub fn get_cert_by_user(&self, user: &User) -> Result<Vec<Cert>> {
        Ok(Cert::belonging_to(user)
            .order(certs::id)
            .load::<Cert>(&self.conn)?)
    }

    pub fn get_certs(&self) -> Result<Vec<Cert>> {
        certs::table
            .load::<Cert>(&self.conn)
            .context("Error loading certs")
    }

    pub fn get_revocations(&self, cert: &Cert) -> Result<Vec<Revocation>> {
        Ok(Revocation::belonging_to(cert).load::<Revocation>(&self.conn)?)
    }

    pub fn add_revocation(
        &self,
        revocation: &str,
        cert: &Cert,
    ) -> Result<Revocation> {
        let hash = &Pgp::revocation_to_hash(revocation)?;

        self.insert_revocation(NewRevocation {
            hash,
            revocation,
            cert_id: cert.id,
            published: false,
        })
    }

    pub fn get_revocation_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<Revocation>> {
        let db: Vec<Revocation> = revocations::table
            .filter(revocations::hash.eq(hash))
            .load::<Revocation>(&self.conn)
            .context("Error loading Revocation by hash")?;

        assert!(
            db.len() <= 1,
            "unexpected duplicate hash in revocations table"
        );

        if let Some(revocation) = db.get(0) {
            Ok(Some(revocation.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn update_revocation(&self, revocation: &Revocation) -> Result<()> {
        diesel::update(revocation)
            .set(revocation)
            .execute(&self.conn)
            .context("Error updating Revocation")?;

        Ok(())
    }

    pub fn get_emails_by_cert(&self, cert: &Cert) -> Result<Vec<CertEmail>> {
        Ok(certs_emails::table
            .filter(certs_emails::cert_id.eq(cert.id))
            .load(&self.conn)
            .expect("could not load emails"))
    }

    pub fn insert_bridge(&self, bridge: NewBridge) -> Result<Bridge> {
        let inserted_count = diesel::insert_into(bridges::table)
            .values(&bridge)
            .execute(&self.conn)
            .context("Error saving new bridge")?;

        if inserted_count != 1 {
            return Err(anyhow::anyhow!(
                "insert_user: insert should return count '1'"
            ));
        }

        let b: Vec<Bridge> = bridges::table
            .order(bridges::id.desc())
            .limit(inserted_count as i64)
            .load(&self.conn)?
            .into_iter()
            .rev()
            .collect();

        if b.len() == 1 {
            Ok(b[0].clone())
        } else {
            Err(anyhow::anyhow!("insert_user: unexpected insert failure"))
        }
    }

    pub fn search_bridge(&self, email: &str) -> Result<Option<Bridge>> {
        let res = bridges::table
            .filter(bridges::email.eq(email))
            .load::<Bridge>(&self.conn)
            .context("Error loading bridge")?;

        match res.len() {
            0 => Ok(None),
            1 => Ok(Some(res[0].clone())),
            _ => Err(anyhow::anyhow!(format!(
                "search_bridge for {} found {} results, expected <=1. \
                 (Database constraints should make this impossible)",
                email,
                res.len()
            ))),
        }
    }

    pub fn list_bridges(&self) -> Result<Vec<Bridge>> {
        Ok(bridges::table
            .load::<Bridge>(&self.conn)
            .context("Error loading bridges")?)
    }

    pub fn diesel_migrations_run(&self) {
        embed_migrations!();

        embedded_migrations::run(&self.conn).unwrap_or_else(|e| {
            panic!("failed to configure database, error {}", e);
        });
    }
}
