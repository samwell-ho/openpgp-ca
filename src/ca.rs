// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenPGP CA as a library
//!
//! Example usage:
//! ```
//! # use openpgp_ca_lib::ca::OpenpgpCa;
//! # use tempfile;
//! // all state of an OpenPGP CA instance is persisted in one SQLite database
//! let db_filename = "/tmp/openpgp-ca.sqlite";
//! # // for Doc-tests we need a random database filename
//! # let file = tempfile::NamedTempFile::new().unwrap();
//! # let db_filename = file.path().to_str().unwrap();
//!
//! // start a new OpenPGP CA instance (implicitely creates the database file)
//! let openpgp_ca = OpenpgpCa::new(Some(db_filename)).expect("Failed to set up CA");
//!
//! // initialize the CA Admin (with domainname and a symbolic name)
//! openpgp_ca.ca_init("example.org", Some("Example Org OpenPGP CA Key")).unwrap();
//!
//! // create a new user, with all signatures
//! // (the private key is printed to stdout and needs to be manually
//! // processed from there)
//! openpgp_ca.user_new(Some(&"Alice"), &["alice@example.org"], None, false).unwrap();
//! ```

use crate::bridge;
use crate::cas;
use crate::cert;
use crate::db::Db;
use crate::export;
use crate::import;
use crate::models;
use crate::pgp::Pgp;
use crate::revocation;

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;

use anyhow::{Context, Result};

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// OpenpgpCa exposes the functionality of OpenPGP CA as a library
/// (the command line utility 'openpgp-ca' is built on top of this library)
pub struct OpenpgpCa {
    pub db: Db, // FIXME
}

impl OpenpgpCa {
    /// Instantiate a new OpenpgpCa object.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter,
    /// - the environment variable OPENPGP_CA_DB, or
    /// - the .env DATABASE_URL
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        let db_url = if let Some(s) = db_url {
            Some(s.to_owned())
        } else if let Ok(database) = env::var("OPENPGP_CA_DB") {
            Some(database)
        } else {
            // load config from .env
            dotenv::dotenv().ok();

            // diesel naming convention for .env
            let env_db = env::var("DATABASE_URL");

            // if unset (or bad), return None
            env_db.ok()
        };

        if let Some(db_url) = db_url {
            let db = Db::new(&db_url)?;
            db.diesel_migrations_run();

            Ok(OpenpgpCa { db })
        } else {
            Err(anyhow::anyhow!("ERROR: no database configuration found"))
        }
    }

    // -------- CAs

    pub fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()> {
        cas::ca_init(&self, domainname, name)
    }

    pub fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        cas::ca_generate_revocations(&self, output)
    }

    pub fn ca_import_tsig(&self, cert: &str) -> Result<()> {
        cas::ca_import_tsig(&self, cert)
    }

    /// Get the Ca and Cacert objects from the database
    ///
    /// The Ca object is permanent and shouldn't change after initial
    /// creation.
    ///
    /// The Cacert contains the Key material for the CA.
    /// When the CA Cert gets updated (e.g. it gets signed by a CA user), the
    /// Cert in the database will be updated.
    ///
    /// If a new Cert gets created for the CA, a new Cacert row is
    /// inserted into the database.
    pub fn ca_get(&self) -> Result<Option<(models::Ca, models::Cacert)>> {
        self.db.get_ca()
    }

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This is the OpenPGP Cert of the CA.
    pub fn ca_get_cert(&self) -> Result<Cert> {
        cas::ca_get_cert(&self)
    }

    pub fn get_ca_domain(&self) -> Result<String> {
        cas::get_ca_domain(&self)
    }

    pub fn get_ca_email(&self) -> Result<String> {
        cas::get_ca_email(&self)
    }

    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        cas::ca_get_pubkey_armored(&self)
    }

    /// Print information about the Ca to stdout.
    ///
    /// This shows the domainname of this OpenPGP CA instance and the
    /// private Cert of the CA.
    pub fn ca_show(&self) -> Result<()> {
        let (ca, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?
            .unwrap();
        println!("\nOpenPGP CA for Domain: {}", ca.domainname);
        println!();
        println!("{}", ca_cert.priv_cert);
        Ok(())
    }
    // -------- users / certs

    /// Get a list of all User Certs
    //
    // FIXME: remove this method ->
    // it's probably always better to explicitly iterate over user,
    // then certs(user)
    pub fn user_certs_get_all(&self) -> Result<Vec<models::Cert>> {
        let users = self.db.get_users_sort_by_name()?;
        let mut user_certs = Vec::new();
        for user in users {
            user_certs.append(&mut self.db.get_cert_by_user(&user)?);
        }
        Ok(user_certs)
    }

    pub fn certs_expired(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
        cert::certs_expired(self, days)
    }

    pub fn cert_check_certifications(
        &self,
        cert: &models::Cert,
    ) -> Result<(Vec<UserID>, bool)> {
        cert::cert_check_certifications(self, cert)
    }

    pub fn cert_check_ca_sig(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<UserID>> {
        cert::cert_check_ca_sig(self, cert)
    }

    pub fn cert_check_tsig_on_ca(&self, cert: &models::Cert) -> Result<bool> {
        cert::cert_check_tsig_on_ca(self, cert)
    }

    pub fn certs_refresh_ca_certifications(
        &self,
        threshold_days: u64,
        validity_days: u64,
    ) -> Result<()> {
        cert::certs_refresh_ca_certifications(
            self,
            threshold_days,
            validity_days,
        )
    }

    pub fn user_new(
        &self,
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
        password: bool,
    ) -> Result<models::User> {
        cert::user_new(&self, name, emails, duration_days, password)
    }

    pub fn cert_import_new(
        &self,
        key: &str,
        revoc_certs: Vec<String>,
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
    ) -> Result<()> {
        cert::cert_import_new(
            self,
            key,
            revoc_certs,
            name,
            emails,
            duration_days,
        )
    }

    pub fn cert_import_update(&self, key: &str) -> Result<()> {
        cert::cert_import_update(self, key)
    }

    /// Update a User in the database
    pub fn user_update(&self, user: &models::User) -> Result<()> {
        self.db.update_user(user)
    }

    /// Update a Cert in the database
    pub fn cert_update(&self, cert: &models::Cert) -> Result<()> {
        self.db.update_cert(cert)
    }

    /// Get Cert by fingerprint.
    ///
    /// If 'fingerprint' contains spaces, they will be
    /// filtered out.
    pub fn cert_get_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<models::Cert>> {
        let norm = Pgp::normalize_fp(fingerprint);
        self.db.get_cert(&norm)
    }

    /// Get a Cert by id
    pub fn cert_by_id(&self, cert_id: i32) -> Result<Option<models::Cert>> {
        self.db.get_cert_by_id(cert_id)
    }

    /// Get a list of all Certs for one User
    pub fn get_certs_by_user(
        &self,
        user: &models::User,
    ) -> Result<Vec<models::Cert>> {
        self.db.get_cert_by_user(&user)
    }

    /// Get a list of all Users, ordered by name
    pub fn users_get_all(&self) -> Result<Vec<models::User>> {
        self.db.get_users_sort_by_name()
    }

    /// Get a list of the Certs that are associated with `email`
    pub fn certs_get(&self, email: &str) -> Result<Vec<models::Cert>> {
        self.db.get_certs_by_email(email)
    }

    /// Get database User(s) for database Cert
    pub fn cert_get_users(
        &self,
        cert: &models::Cert,
    ) -> Result<Option<models::User>> {
        self.db.get_user_by_cert(cert)
    }

    /// Get a user name that is associated with this Cert.
    ///
    /// The name is only for display purposes, it is set to "<no name>" if
    /// no name can be found, or to "<multiple users>" if the Cert is
    /// associated with more than one User.
    pub fn cert_get_name(&self, cert: &models::Cert) -> Result<String> {
        if let Some(user) = self.cert_get_users(cert)? {
            Ok(user.name.unwrap_or_else(|| "<no name>".to_string()))
        } else {
            Ok("<no name>".to_string())
        }
    }

    // -------- revocations

    /// Get a list of all Revocations for a cert
    pub fn revocations_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(cert)
    }

    pub fn revocation_add(&self, revoc_cert_str: &str) -> Result<()> {
        revocation::revocation_add(&self, revoc_cert_str)
    }

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    pub fn revocation_add_from_file(&self, filename: &PathBuf) -> Result<()> {
        let mut s = String::new();
        File::open(filename)?.read_to_string(&mut s)?;
        self.revocation_add(&s)
    }

    /// Get a Revocation by hash
    pub fn revocation_get_by_hash(
        &self,
        hash: &str,
    ) -> Result<models::Revocation> {
        if let Some(rev) = self.db.get_revocation_by_hash(hash)? {
            Ok(rev)
        } else {
            Err(anyhow::anyhow!("no revocation found"))
        }
    }

    pub fn revocation_apply(&self, revoc: models::Revocation) -> Result<()> {
        revocation::revocation_apply(&self, revoc)
    }

    /// Get reason and creation time for a Revocation
    pub fn revocation_details(
        revocation: &models::Revocation,
    ) -> Result<(String, Option<SystemTime>)> {
        let rev = Pgp::armored_to_signature(&revocation.revocation)?;

        let creation = rev.signature_creation_time();

        if let Some((code, reason)) = rev.reason_for_revocation() {
            let reason = String::from_utf8(reason.to_vec())?;
            Ok((format!("{} ({})", code.to_string(), reason), creation))
        } else {
            Ok(("Revocation reason unknown".to_string(), creation))
        }
    }

    /// Get an armored representation of a revocation certificate
    pub fn revoc_to_armored(sig: &Signature) -> Result<String> {
        Pgp::revoc_to_armored(sig, None)
    }

    // -------- emails

    /// Get all Emails for a Cert
    pub fn emails_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::CertEmail>> {
        self.db.get_emails_by_cert(cert)
    }

    pub fn get_emails_all(&self) -> Result<Vec<models::CertEmail>> {
        self.db.get_emails_all()
    }

    // --------- bridges

    /// Get a list of Bridges
    pub fn bridges_get(&self) -> Result<Vec<models::Bridge>> {
        self.db.list_bridges()
    }

    /// Get a specific Bridge
    pub fn bridges_search(&self, email: &str) -> Result<models::Bridge> {
        if let Some(bridge) = self.db.search_bridge(email)? {
            Ok(bridge)
        } else {
            Err(anyhow::anyhow!("bridge not found"))
        }
    }

    pub fn add_bridge(
        &self,
        email: Option<&str>,
        key_file: &PathBuf,
        scope: Option<&str>,
        commit: bool,
    ) -> Result<()> {
        if commit {
            let (bridge, fingerprint) =
                bridge::bridge_new(&self, key_file, email, scope)?;

            println!("Signed OpenPGP key for {} as bridge.\n", bridge.email);
            println!("The fingerprint of the remote CA key is");
            println!("{}\n", fingerprint);
        } else {
            println!("Bridge creation DRY RUN.");
            println!();

            println!(
                "Please verify that this is the correct fingerprint for the \
            remote CA admin before continuing:"
            );
            println!();

            let key = std::fs::read_to_string(key_file)?;
            Pgp::print_cert_info(&key)?;

            println!();
            println!(
                "When you've confirmed that the remote key is correct, repeat \
            this command with the additional parameter '--commit' \
            to commit the OpenPGP CA bridge to the database."
            );
        }
        Ok(())
    }

    pub fn bridge_revoke(&self, email: &str) -> Result<()> {
        bridge::bridge_revoke(self, email)
    }

    pub fn print_bridges(&self, email: Option<String>) -> Result<()> {
        let bridges = if let Some(email) = email {
            vec![self.bridges_search(&email)?]
        } else {
            self.bridges_get()?
        };

        for bridge in bridges {
            let cert = self.cert_by_id(bridge.cert_id)?;
            println!("{}", cert.unwrap().pub_cert);
        }

        Ok(())
    }

    pub fn list_bridges(&self) -> Result<()> {
        self.bridges_get()?.iter().for_each(|bridge| {
            println!(
                "Bridge to '{}', (scope: '{}'",
                bridge.email, bridge.scope
            )
        });
        Ok(())
    }

    // -------- export

    pub fn export_certs_as_files(
        &self,
        email_filter: Option<String>,
        path: Option<String>,
    ) -> Result<()> {
        export::export_certs_as_files(&self, email_filter, path)
    }

    pub fn wkd_export(&self, domain: &str, path: &Path) -> Result<()> {
        export::wkd_export(&self, domain, path)
    }

    pub fn export_keylist(
        &self,
        path: PathBuf,
        signature_uri: String,
        force: bool,
    ) -> Result<()> {
        export::export_keylist(&self, path, signature_uri, force)
    }

    // -------- update keys from public key sources

    pub fn update_from_wkd(&self, cert: &models::Cert) -> Result<()> {
        import::update_from_wkd(&self, cert)
    }

    pub fn update_from_hagrid(&self, cert: &models::Cert) -> Result<()> {
        import::update_from_hagrid(&self, cert)
    }
}
