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
//! openpgp_ca.user_new(Some(&"Alice"), &["alice@example.org"], None, false, false).unwrap();
//! ```

use crate::bridge;
use crate::ca_public::CaPub;
use crate::ca_secret::CaSec;
use crate::cert;
use crate::db::models;
use crate::db::OcaDb;
use crate::export;
use crate::import;
use crate::pgp::Pgp;
use crate::revocation;

use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::Cert;

use anyhow::{Context, Result};
use chrono::offset::Utc;
use chrono::DateTime;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

/// a DB backend for a CA instance
pub(crate) struct DbCa {
    db: Rc<OcaDb>,
}

impl DbCa {
    pub fn new(db: Rc<OcaDb>) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &OcaDb {
        &self.db
    }
}

/// OpenpgpCa exposes the functionality of OpenPGP CA as a library
/// (the command line utility 'openpgp-ca' is built on top of this library)
pub struct OpenpgpCa {
    db: Rc<OcaDb>,

    ca_public: Rc<dyn CaPub>,
    ca_secret: Rc<dyn CaSec>,
}

impl OpenpgpCa {
    /// Instantiate a new OpenpgpCa object.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter,
    /// - the environment variable OPENPGP_CA_DB, or
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        let db_url = if let Some(url) = db_url {
            url.to_owned()
        } else if let Ok(database) = env::var("OPENPGP_CA_DB") {
            database
        } else {
            return Err(anyhow::anyhow!(
                "ERROR: no database configuration found"
            ));
        };

        let db = Rc::new(OcaDb::new(&db_url)?);
        db.diesel_migrations_run();

        let dbca = Rc::new(DbCa::new(db.clone()));

        Ok(OpenpgpCa {
            db,

            ca_secret: dbca.clone(),
            ca_public: dbca,
        })
    }

    pub fn db(&self) -> &OcaDb {
        &self.db
    }

    // -------- CAs

    /// Initialize OpenPGP CA Admin database entry.
    ///
    /// This generates a new OpenPGP Key for the Admin role and stores the
    /// private Key in the OpenPGP CA database.
    ///
    /// `domainname` is the domain that this CA Admin is in charge of,
    /// `name` is a descriptive name for the CA Admin
    ///
    /// Only one CA Admin can be configured per database.
    pub fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()> {
        self.ca_secret.ca_init(domainname, name)
    }

    /// Generate a set of revocation certificates for the CA key.
    ///
    /// This outputs a set of revocations with creation dates spaced
    /// in 30 day increments, from now to 120x 30days in the future (around
    /// 10 years). For each of those points in time, one hard and one soft
    /// revocation certificate is generated.
    ///
    /// The output file is human readable, contains some informational
    /// explanation, followed by the CA certificate and the list of
    /// revocation certificates
    pub fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        self.ca_secret.ca_generate_revocations(&self, output)
    }

    /// Add trust-signature(s) from CA users to the CA's Cert.
    ///
    /// This receives an armored version of the CA's public key, finds
    /// any trust-signatures on it and merges those into "our" local copy of
    /// the CA key.
    pub fn ca_import_tsig(&self, cert: &str) -> Result<()> {
        self.ca_secret.ca_import_tsig(cert)
    }

    /// Generate a detached signature with the CA key, for 'text'
    pub(crate) fn sign_detached(&self, text: &str) -> Result<String> {
        self.ca_secret.sign_detached(text)
    }

    pub(crate) fn sign_user_emails(
        &self,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        self.ca_secret.sign_user_emails(
            user_cert,
            emails_filter,
            duration_days,
        )
    }

    pub(crate) fn sign_user_ids(
        &self,
        user_cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        self.ca_secret
            .sign_user_ids(user_cert, uids_certify, duration_days)
    }

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This returns a stripped version of the CA Cert, without private key
    /// material.
    ///
    /// This is the OpenPGP Cert of the CA.
    pub fn ca_get_cert_pub(&self) -> Result<Cert> {
        self.ca_public.ca_get_cert_pub()
    }

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This returns a full version of the CA Cert, including private key
    /// material.
    ///
    /// This is the OpenPGP Cert of the CA.
    ///
    /// CAUTION: this should only by used in tests. getting private key
    /// material is not possible with some secret key backends!
    pub fn ca_get_cert_priv(&self) -> Result<Cert> {
        self.ca_secret.ca_get_priv_key()
    }

    /// Get the domainname for this CA
    pub fn get_ca_domain(&self) -> Result<String> {
        self.ca_public.get_ca_domain()
    }

    /// Get the email of this CA
    pub fn get_ca_email(&self) -> Result<String> {
        self.ca_public.get_ca_email()
    }

    /// Returns the public key of the CA as an armored String
    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        self.ca_public.ca_get_pubkey_armored()
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

    /// Which certs will be expired in 'days' days?
    ///
    /// If a cert is not "alive" now, it will not get returned as expiring.
    /// (Otherwise old/abandoned certs would clutter the results)
    pub fn certs_expired(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
        cert::certs_expired(self, days)
    }

    /// For each Cert, check if:
    /// - the Cert has been signed by the CA, and
    /// - the CA key has a trust-signature from the Cert
    ///
    /// Returns a map 'cert -> (sig_from_ca, tsig_on_ca)'
    pub fn cert_check_certifications(
        &self,
        cert: &models::Cert,
    ) -> Result<(Vec<UserID>, bool)> {
        cert::cert_check_certifications(self, cert)
    }

    /// Check if this Cert has been signed by the CA Key
    pub fn cert_check_ca_sig(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<UserID>> {
        cert::cert_check_ca_sig(self, cert)
    }

    /// Check if this Cert has tsigned the CA Key
    pub fn cert_check_tsig_on_ca(&self, cert: &models::Cert) -> Result<bool> {
        cert::cert_check_tsig_on_ca(self, cert)
    }

    /// Check all Certs for certifications from the CA.
    ///
    /// If a certification expires in less than `threshold_days`, and it is
    /// not marked as 'inactive', make a new certification that is good for
    /// `validity_days`, and update the Cert.
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

    /// Create a new OpenPGP CA User.
    ///
    /// The CA Cert is automatically trust-signed with this new user
    /// Cert and the user Cert is signed by the CA. This is the
    /// "Centralized key creation workflow"
    ///
    /// This generates a new OpenPGP Cert for the new User.
    /// The private Cert material is printed to stdout and NOT stored
    /// in OpenPGP CA.
    ///
    /// The public Cert is stored in the OpenPGP CA database.
    pub fn user_new(
        &self,
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
        password: bool,
        output_format_minimal: bool,
    ) -> Result<models::User> {
        cert::user_new(
            &self,
            name,
            emails,
            duration_days,
            password,
            output_format_minimal,
        )
    }

    /// Import an existing OpenPGP public Cert a new OpenPGP CA user.
    ///
    /// The `key` is expected as an armored public key.
    ///
    /// userids that correspond to `emails` will be signed by the CA.
    ///
    /// A symbolic `name` and a list of `emails` for this User can
    /// optionally be supplied. If those are not set, emails are taken from
    /// the list of userids in the public key. Also, if the
    /// key has exactly one userid, the symbolic name is taken from that
    /// userid.
    ///
    /// Optionally a revocation certificate can be supplied.
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

    /// Update key for existing database Cert
    pub fn cert_import_update(&self, key: &str) -> Result<()> {
        cert::cert_import_update(self, key)
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

    pub fn print_certifications_status(&self) -> Result<()> {
        let mut count_ok = 0;

        let users = self.users_get_all()?;
        for user in &users {
            for cert in self.get_certs_by_user(&user)? {
                let (sig_from_ca, tsig_on_ca) =
                    self.cert_check_certifications(&cert)?;

                let ok = if !sig_from_ca.is_empty() {
                    true
                } else {
                    println!(
                        "No CA certification on any User ID of {}.",
                        cert.fingerprint
                    );
                    false
                } && if tsig_on_ca {
                    true
                } else {
                    println!(
                        "CA Cert has not been tsigned by {}.",
                        cert.fingerprint
                    );
                    false
                };

                if ok {
                    count_ok += 1;
                }
            }
        }

        println!();
        println!(
            "Checked {} user keys, {} of them had good certifications in both \
        directions.",
            users.len(),
            count_ok
        );

        Ok(())
    }

    pub fn print_expiry_status(&self, exp_days: u64) -> Result<()> {
        let expiries = self.certs_expired(exp_days)?;

        if expiries.is_empty() {
            println!(
                "No certificates will expire in the next {} days.",
                exp_days
            );
        } else {
            println!(
                "The following {} certificates will expire in the next {} days.",
                expiries.len(),
                exp_days
            );
            println!();
        }

        for (cert, expiry) in expiries {
            let name = self.cert_get_name(&cert)?;
            println!("name {}, fingerprint {}", name, cert.fingerprint);

            if let Some(exp) = expiry {
                let datetime: DateTime<Utc> = exp.into();
                println!(" expires: {}", datetime.format("%d/%m/%Y"));
            } else {
                println!(" no expiration date is set for this user key");
            }

            println!();
        }

        Ok(())
    }

    pub fn print_users(&self) -> Result<()> {
        for user in self.users_get_all()? {
            let name =
                user.name.clone().unwrap_or_else(|| "<no name>".to_owned());

            for cert in self.get_certs_by_user(&user)? {
                let (sig_by_ca, tsig_on_ca) =
                    self.cert_check_certifications(&cert)?;

                println!("OpenPGP key {}", cert.fingerprint);
                println!(" for user '{}'", name);

                println!(" user cert signed by CA: {}", !sig_by_ca.is_empty());
                println!(" user cert has tsigned CA: {}", tsig_on_ca);

                let c = Pgp::armored_to_cert(&cert.pub_cert)?;

                self.emails_get(&cert)?
                    .iter()
                    .for_each(|email| println!(" - email {}", email.addr));

                if let Some(exp) = Pgp::get_expiry(&c)? {
                    let datetime: DateTime<Utc> = exp.into();
                    println!(" expires: {}", datetime.format("%d/%m/%Y"));
                } else {
                    println!(" no expiration date is set for this user key");
                }

                let revs = self.revocations_get(&cert)?;
                println!(
                    " {} revocation certificate(s) available",
                    revs.len()
                );

                if Pgp::is_possibly_revoked(&c) {
                    println!(" this user key has (possibly) been REVOKED");
                }
                println!();
            }
        }

        Ok(())
    }

    // -------- revocations

    /// Get a list of all Revocations for a cert
    pub fn revocations_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(cert)
    }

    /// Add a revocation certificate to the OpenPGP CA database.
    ///
    /// The matching cert is looked up by issuer Fingerprint, if
    /// possible - or by exhaustive search otherwise.
    ///
    /// Verifies that applying the revocation cert can be validated by the
    /// cert. Only if this is successful is the revocation stored.
    pub fn revocation_add(&self, revoc_cert_str: &str) -> Result<()> {
        revocation::revocation_add(&self, revoc_cert_str)
    }

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    pub fn revocation_add_from_file(&self, filename: &Path) -> Result<()> {
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

    /// Apply a revocation.
    ///
    /// The revocation is merged into out copy of the OpenPGP Cert.
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

    pub fn print_revocations(&self, email: &str) -> Result<()> {
        let certs = self.certs_get(email)?;
        if certs.is_empty() {
            println!("No OpenPGP keys found");
        } else {
            for cert in certs {
                let name = self.cert_get_name(&cert)?;

                println!(
                    "Revocations for OpenPGP key {}, user \"{}\"",
                    cert.fingerprint, name
                );
                let revoc = self.revocations_get(&cert)?;
                for r in revoc {
                    let (reason, time) = Self::revocation_details(&r)?;
                    let time = if let Some(time) = time {
                        let datetime: DateTime<Utc> = time.into();
                        format!("{}", datetime.format("%d/%m/%Y"))
                    } else {
                        "".to_string()
                    };
                    println!(
                        " - revocation id {}: {} ({})",
                        r.hash, reason, time
                    );
                    if r.published {
                        println!("   this revocation has been APPLIED");
                    }

                    println!();
                }
            }
        }
        Ok(())
    }

    // -------- emails

    /// Get all Emails for a Cert
    pub fn emails_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::CertEmail>> {
        self.db.get_emails_by_cert(cert)
    }

    /// Get all Emails
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
        key_file: &Path,
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

    /// Create a revocation Certificate for a Bridge and apply it the our
    /// copy of the remote CA's public key.
    ///
    /// Both the revoked remote public key and the revocation cert are
    /// printed to stdout.
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

    pub(crate) fn bridge_to_remote_ca(
        &self,
        remote_ca_cert: Cert,
        regexes: Vec<String>,
    ) -> Result<Cert> {
        self.ca_secret.bridge_to_remote_ca(remote_ca_cert, regexes)
    }

    // -------- export

    /// Export all user keys (that have a userid in `domain`) and the CA key
    /// into a wkd directory structure
    ///
    /// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08
    pub fn export_wkd(&self, domain: &str, path: &Path) -> Result<()> {
        export::wkd_export(&self, domain, path)
    }

    /// Export the contents of a CA in Keylist format.
    ///
    /// `path`: filesystem path into which the exported keylist and signature
    /// files will be written.
    ///
    /// `signature_uri`: the https address from which the signature file will
    /// be retrievable
    ///
    /// `force`: by default, this fn fails if the files exist; when force is
    /// true, overwrite.
    pub fn export_keylist(
        &self,
        path: PathBuf,
        signature_uri: String,
        force: bool,
    ) -> Result<()> {
        export::export_keylist(&self, path, signature_uri, force)
    }

    /// Export Certs from this CA into files, with filenames based on email
    /// addresses of user ids.
    pub fn export_certs_as_files(
        &self,
        email_filter: Option<String>,
        path: Option<String>,
    ) -> Result<()> {
        export::export_certs_as_files(&self, email_filter, path)
    }

    // -------- update keys from public key sources

    /// Pull a key from WKD and merge any updates into our local version of
    /// this key
    pub fn update_from_wkd(&self, cert: &models::Cert) -> Result<()> {
        import::update_from_wkd(&self, cert)
    }

    /// Pull a key from hagrid and merge any updates into our local version of
    /// this key
    pub fn update_from_hagrid(&self, cert: &models::Cert) -> Result<()> {
        import::update_from_hagrid(&self, cert)
    }
}
