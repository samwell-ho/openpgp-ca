// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
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

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;

use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::{Cert, Fingerprint, KeyID, Packet};

use crate::db::Db;
use crate::models;
use crate::pgp::Pgp;

use diesel::prelude::*;

use crate::models::Revocation;
use anyhow::{Context, Result};
use sequoia_openpgp::KeyHandle;
use std::fs::File;
use std::io::Read;

/// OpenpgpCa exposes the functionality of OpenPGP CA as a library
/// (the command line utility 'openpgp-ca' is built on top of this library)
pub struct OpenpgpCa {
    db: Db,
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
        if self.db.get_ca()?.is_some() {
            return Err(
                anyhow::anyhow!("ERROR: CA has already been created",),
            );
        }

        // domainname syntax check
        if !publicsuffix::Domain::has_valid_syntax(domainname) {
            return Err(anyhow::anyhow!(
                "Parameter is not a valid domainname",
            ));
        }

        let name = match name {
            Some(name) => Some(name),
            _ => Some("OpenPGP CA"),
        };

        let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

        let ca_key = &Pgp::cert_to_armored_private_key(&cert)?;

        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            self.db.insert_ca(
                models::NewCa { domainname },
                ca_key,
                &cert.fingerprint().to_hex(),
            )?;

            Ok(())
        })
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
    /// This is the "private" OpenPGP Cert of the CA.
    pub fn ca_get_cert(&self) -> Result<Cert> {
        match self.db.get_ca()? {
            Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.priv_cert)?),
            _ => panic!("get_ca_cert() failed"),
        }
    }

    /// get the domainname of this CA
    pub fn get_ca_domain(&self) -> Result<String> {
        let cert = self.ca_get_cert()?;
        let uids: Vec<_> = cert.userids().collect();

        if uids.len() != 1 {
            return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
        }

        let email = &uids[0].userid().email()?;

        if let Some(email) = email {
            let split: Vec<_> = email.split('@').collect();

            if split.len() == 2 {
                Ok(split[1].to_owned())
            } else {
                Err(anyhow::anyhow!(
                    "ERROR: Error while splitting domain from CA user_id "
                ))
            }
        } else {
            Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
        }
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

    /// Returns the public key of the CA as an armored String
    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        let cert = self.ca_get_cert()?;
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    /// Add trust-signature(s) from CA users to the CA's Cert.
    ///
    /// This receives an armored version of the CA's public key, finds
    /// any trust-signatures on it and merges those into "our" local copy of
    /// the CA key.
    pub fn ca_import_tsig(&self, key: &str) -> Result<()> {
        use diesel::prelude::*;
        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let ca_cert = self.ca_get_cert().unwrap();

            let cert_import = Pgp::armored_to_cert(key)?;

            // make sure the keys have the same Fingerprint
            if ca_cert.fingerprint() != cert_import.fingerprint() {
                return Err(anyhow::anyhow!(
                    "The imported cert has an unexpected Fingerprint",
                ));
            }

            // get the tsig(s) from import
            let tsigs = Self::get_trust_sigs(&cert_import)?;

            // add tsig(s) to our "own" version of the CA key
            let mut packets: Vec<Packet> = Vec::new();
            tsigs.iter().for_each(|s| packets.push(s.clone().into()));

            let signed = ca_cert
                .insert_packets(packets)
                .context("merging tsigs into CA Key failed")?;

            // update in DB
            let (_, mut ca_cert) = self
                .db
                .get_ca()
                .context("failed to load CA from database")?
                .unwrap();

            ca_cert.priv_cert = Pgp::cert_to_armored_private_key(&signed)
                .context("failed to armor CA Cert")?;

            self.db
                .update_cacert(&ca_cert)
                .context("Update of CA Cert in DB failed")?;

            Ok(())
        })
    }

    // -------- users / certs

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
    ) -> Result<models::User> {
        let ca_cert = self.ca_get_cert()?;

        // make user cert (signed by CA)
        let (user_cert, revoc, pass) =
            Pgp::make_user_cert(emails, name, password)
                .context("make_user failed")?;

        // sign user key with CA key
        let certified = Pgp::sign_user_emails(
            &ca_cert,
            &user_cert,
            Some(emails),
            duration_days,
        )
        .context("sign_user failed")?;

        // user tsigns CA key
        let tsigned_ca = Pgp::tsign_ca(ca_cert, &user_cert, pass.as_deref())
            .context("failed: user tsigns CA")?;

        let tsigned_ca_armored =
            Pgp::cert_to_armored_private_key(&tsigned_ca)?;

        let pub_key = &Pgp::cert_to_armored(&certified)?;
        let revoc = Pgp::sig_to_armored(&revoc)?;

        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let res = self.db.add_user(
                name,
                (pub_key, &user_cert.fingerprint().to_hex()),
                emails,
                &[revoc],
                Some(&tsigned_ca_armored),
            );

            if res.is_err() {
                eprint!("{:?}", res);
                return Err(anyhow::anyhow!("Couldn't insert user"));
            }

            // the private key needs to be handed over to the user, print for now
            println!(
                "new user key for {}:\n{}",
                name.unwrap_or(""),
                &Pgp::cert_to_armored_private_key(&certified)?
            );
            if let Some(pass) = pass {
                println!("Password for this key: '{}'.\n", pass);
            } else {
                println!("No password set for this key.\n");
            }
            // --

            Ok(res?)
        })
    }

    /// Update a User in the database
    pub fn user_update(&self, user: &models::User) -> Result<()> {
        self.db.update_user(user)
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
        let c = Pgp::armored_to_cert(key)
            .context("cert_import_new: couldn't process key")?;

        let fingerprint = &c.fingerprint().to_hex();

        let exists = self.db.get_cert(fingerprint).context(
            "cert_import_new: error while checking for \
            existing cert with the same fingerprint",
        )?;

        if exists.is_some() {
            return Err(anyhow::anyhow!(
                "A cert with this ingerprint already exists in the DB"
            ));
        }

        // sign user key with CA key
        let ca_cert = self.ca_get_cert()?;

        // sign only the User IDs that have been specified
        let certified =
            Pgp::sign_user_emails(&ca_cert, &c, Some(emails), duration_days)
                .context("sign_user_emails failed")?;

        // use name from User IDs, if no name was passed
        let name = match name {
            Some(name) => Some(name.to_owned()),
            None => {
                let userids: Vec<_> = c.userids().collect();
                if userids.len() == 1 {
                    let userid = &userids[0];
                    userid.userid().name()?
                } else {
                    None
                }
            }
        };

        let pub_key = &Pgp::cert_to_armored(&certified)
            .context("cert_import_new: couldn't re-armor key")?;

        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let res = self.db.add_user(
                name.as_deref(),
                (pub_key, fingerprint),
                &emails,
                &revoc_certs,
                None,
            );

            if res.is_err() {
                eprint!("{:?}", res);
                return Err(anyhow::anyhow!("Couldn't insert user"));
            }

            Ok(())
        })
    }

    /// Update key for existing database Cert
    pub fn cert_import_update(&self, key: &str) -> Result<()> {
        let cert_new = Pgp::armored_to_cert(key)
            .context("cert_import_new: couldn't process key")?;

        let fingerprint = &cert_new.fingerprint().to_hex();

        let exists = self.db.get_cert(fingerprint).context(
            "cert_import_update: error while checking for \
            existing cert with the same fingerprint",
        )?;

        if let Some(mut cert) = exists {
            // merge existing and new public key
            let cert_old = Pgp::armored_to_cert(&cert.pub_cert)?;

            let updated = cert_old.merge_public(cert_new)?;
            let armored = Pgp::cert_to_armored(&updated)?;

            cert.pub_cert = armored;
            self.db.update_cert(&cert)?;
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "No cert with this fingerprint exists in the DB, cannot \
                update"
            ))
        }
    }

    /// Update a Cert in the database
    pub fn cert_update(&self, cert: &models::Cert) -> Result<()> {
        self.db.update_cert(cert)
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
        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let ca_cert = self.ca_get_cert()?;
            let ca_fp = ca_cert.fingerprint();

            let threshold_secs = threshold_days * 24 * 60 * 60;
            let threshold_time =
                SystemTime::now() + Duration::new(threshold_secs, 0);

            for cert in self
                .db
                .get_certs()?
                .iter()
                // ignore "inactive" Certs
                .filter(|c| !c.inactive)
            {
                let c = OpenpgpCa::armored_to_cert(&cert.pub_cert)?;
                let mut uids_to_recert = Vec::new();

                for uid in c.userids() {
                    let ca_certifications: Vec<_> = uid
                        .certifications()
                        .filter(|c| {
                            c.issuer_fingerprints().any(|fp| *fp == ca_fp)
                        })
                        .collect();

                    let sig_valid_past_threshold = |c: &&Signature| {
                        let expiration = c.signature_expiration_time();
                        expiration.is_none()
                            || (expiration.unwrap() > threshold_time)
                    };

                    // a new certification is created if certifications by the
                    // CA exist, but none of the existing certifications are
                    // valid for longer than `threshold_days`
                    if !ca_certifications.is_empty()
                        && !ca_certifications
                            .iter()
                            .any(sig_valid_past_threshold)
                    {
                        // make a new certification for this uid
                        uids_to_recert.push(uid.userid());
                    }
                }
                if !uids_to_recert.is_empty() {
                    // make new certifications for "uids_to_update"
                    let recertified = Pgp::sign_user_ids(
                        &ca_cert,
                        &c,
                        &uids_to_recert[..],
                        Some(validity_days),
                    )?;

                    // update cert in db
                    let mut cert_update = cert.clone();
                    cert_update.pub_cert =
                        OpenpgpCa::cert_to_armored(&recertified)?;
                    self.cert_update(&cert_update)?;
                }
            }

            Ok(())
        })
    }

    /// Get the SystemTime for when the specified Cert will expire
    pub fn cert_expiration(cert: &models::Cert) -> Result<Option<SystemTime>> {
        let cert = Pgp::armored_to_cert(&cert.pub_cert)?;
        Ok(Pgp::get_expiry(&cert)?)
    }

    /// Which certs will be expired in 'days' days?
    pub fn certs_expired(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Cert, (bool, Option<SystemTime>)>> {
        let mut map = HashMap::new();

        let days = Duration::new(60 * 60 * 24 * days, 0);
        let expiry_test = SystemTime::now().checked_add(days).unwrap();

        let certs =
            self.user_certs_get_all().context("couldn't load certs")?;

        for cert in certs {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;
            let exp = Pgp::get_expiry(&c)?;
            let alive = c
                .with_policy(&StandardPolicy::new(), expiry_test)?
                .alive()
                .is_ok();
            // cert.alive(&StandardPolicy::new(), expiry_test).is_ok();

            map.insert(cert, (alive, exp));
        }

        Ok(map)
    }

    /// Check if a cert is "possibly revoked"
    pub fn cert_possibly_revoked(cert: &models::Cert) -> Result<bool> {
        let cert = Pgp::armored_to_cert(&cert.pub_cert)?;
        Ok(Pgp::is_possibly_revoked(&cert))
    }

    /// For each Cert, check if:
    /// - the Cert has been signed by the CA, and
    /// - the CA key has a trust-signature from the Cert
    ///
    /// Returns a map 'cert -> (sig_from_ca, tsig_on_ca)'
    pub fn cert_check_certifications(
        &self,
        cert: &models::Cert,
    ) -> Result<(bool, bool)> {
        let sig_from_ca = self
            .cert_check_ca_sig(&cert)
            .context("Failed while checking CA sig")?;

        let tsig_on_ca = self
            .cert_check_tsig_on_ca(&cert)
            .context("Failed while checking tsig on CA")?;

        Ok((sig_from_ca, tsig_on_ca))
    }

    /// Check if this Cert has been signed by the CA Key
    pub fn cert_check_ca_sig(&self, cert: &models::Cert) -> Result<bool> {
        let user_cert = Pgp::armored_to_cert(&cert.pub_cert)?;
        let sigs = Self::get_third_party_sigs(&user_cert)?;

        let ca = self.ca_get_cert()?;

        Ok(sigs
            .iter()
            .any(|s| s.issuer_fingerprints().any(|f| f == &ca.fingerprint())))
    }

    /// Check if this Cert has tsigned the CA Key
    pub fn cert_check_tsig_on_ca(&self, cert: &models::Cert) -> Result<bool> {
        let ca = self.ca_get_cert()?;
        let tsigs = Self::get_trust_sigs(&ca)?;

        let user_cert = Pgp::armored_to_cert(&cert.pub_cert)?;

        Ok(tsigs.iter().any(|t| {
            t.issuer_fingerprints()
                .any(|fp| fp == &user_cert.fingerprint())
        }))
    }

    /// Get sequoia Cert representation of a database Cert
    pub fn cert_to_cert(cert: &models::Cert) -> Result<Cert> {
        Pgp::armored_to_cert(&cert.pub_cert)
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

    /// Get the Cert representation of an armored key
    pub fn armored_to_cert(armored: &str) -> Result<Cert> {
        Pgp::armored_to_cert(armored)
    }

    /// Get a Vec of Cert from an ascii armored keyring
    pub fn armored_keyring_to_certs(armored: &str) -> Result<Vec<Cert>> {
        Pgp::armored_keyring_to_certs(armored)
    }

    /// Get the armored "public key" representation of a Cert
    pub fn cert_to_armored(cert: &Cert) -> Result<String> {
        Pgp::cert_to_armored(cert)
    }

    /// Get the armored "keyring" representation of a List of public-key Certs
    pub fn certs_to_armored(certs: &[Cert]) -> Result<String> {
        Pgp::certs_to_armored(certs)
    }

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

    /// Filter spaces so that pretty-printed fingerprint strings can be used
    fn normalize_fp(fp: &str) -> String {
        fp.chars().filter(|&c| c != ' ').collect()
    }

    /// Get Cert by fingerprint.
    ///
    /// If 'fingerprint' contains spaces, they will be
    /// filtered out.
    pub fn cert_get_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<models::Cert>> {
        let norm = OpenpgpCa::normalize_fp(fingerprint);
        self.db.get_cert(&norm)
    }

    /// Get a Cert by id
    pub fn cert_by_id(&self, cert_id: i32) -> Result<Option<models::Cert>> {
        self.db.get_cert_by_id(cert_id)
    }

    // -------- revocations

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    pub fn revocation_add_from_file(&self, filename: &PathBuf) -> Result<()> {
        let mut s = String::new();
        File::open(filename)?.read_to_string(&mut s)?;
        self.revocation_add(&s)
    }

    /// Check if the CA database has a variant of the revocation
    /// certificate 'rev_cert' (according to Signature::normalized_eq()).
    fn check_for_equivalent_revocation(
        &self,
        rev_cert: &Signature,
        cert: &models::Cert,
    ) -> Result<bool> {
        for db_rev in self.db.get_revocations(cert)? {
            let r = Pgp::armored_to_signature(&db_rev.revocation)
                .context("Couldn't re-armor revocation cert from CA db")?;

            if rev_cert.normalized_eq(&r) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Add a revocation certificate to the OpenPGP CA database.
    ///
    /// The matching cert is looked up by issuer Fingerprint, if
    /// possible - or by exhaustive search otherwise.
    ///
    /// Verifies that applying the revocation cert can be validated by the
    /// cert. Only if this is successful is the revocation stored.
    pub fn revocation_add(&self, revoc_cert_str: &str) -> Result<()> {
        // check if the exact same revocation already exists in db
        if self.db.check_for_revocation(revoc_cert_str)? {
            return Ok(()); // this revocation is already stored -> do nothing
        }

        let mut revoc_cert = Pgp::armored_to_signature(revoc_cert_str)
            .context("Couldn't process revocation cert")?;

        // find the matching cert for this revocation certificate
        let mut cert = None;
        // - search by fingerprint, if possible
        if let Some(sig_fingerprint) = Pgp::get_revoc_issuer_fp(&revoc_cert) {
            cert = self.db.get_cert(&sig_fingerprint.to_hex())?;
        }
        // - if match by fingerprint failed: test all certs
        if cert.is_none() {
            cert = self.search_revocable_cert_by_keyid(&mut revoc_cert)?;
        }

        if let Some(cert) = cert {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;

            // verify that revocation certificate validates with cert
            if Self::validate_revocation(&c, &mut revoc_cert)? {
                if !self.check_for_equivalent_revocation(&revoc_cert, &cert)? {
                    // update sig in DB
                    let armored = Pgp::sig_to_armored(&revoc_cert)
                        .context("couldn't armor revocation cert")?;

                    self.db.add_revocation(&armored, &cert)?;
                }

                Ok(())
            } else {
                let msg = format!(
                    "revocation couldn't be matched to a cert: {:?}",
                    revoc_cert
                );

                Err(anyhow::anyhow!(msg))
            }
        } else {
            Err(anyhow::anyhow!("couldn't find cert for this fingerprint"))
        }
    }

    /// verify that applying `revoc_cert` to `cert` yields a new validated
    /// self revocation
    fn validate_revocation(
        cert: &Cert,
        revoc_cert: &mut Signature,
    ) -> Result<bool> {
        let before = cert.primary_key().self_revocations().count();

        let revoked = cert.to_owned().insert_packets(revoc_cert.to_owned())?;

        let after = revoked.primary_key().self_revocations().count();

        // expecting an additional self_revocation after merging revoc_cert
        if before + 1 != after {
            return Ok(false);
        }

        // does the self revocation verify?
        let key = revoked.primary_key().key();
        Ok(revoc_cert.verify_primary_key_revocation(key, key).is_ok())
    }

    /// Search all certs for the one that `revoc` can revoke.
    ///
    /// This assumes that the Signature has no issuer fingerprint.
    /// So if the Signature also has no issuer KeyID, it fails to find a
    /// cert.
    fn search_revocable_cert_by_keyid(
        &self,
        mut revoc: &mut Signature,
    ) -> Result<Option<models::Cert>> {
        let revoc_keyhandles = revoc.get_issuers();
        if revoc_keyhandles.is_empty() {
            return Err(anyhow::anyhow!("Signature has no issuer KeyID"));
        }

        for cert in self.user_certs_get_all()? {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;

            // require that keyid of cert and Signature issuer match
            let c_keyid = c.keyid();

            if !revoc_keyhandles.contains(&KeyHandle::KeyID(c_keyid)) {
                // ignore certs with non-matching KeyID
                continue;
            }

            // if KeyID matches, check if revocation validates
            if Self::validate_revocation(&c, &mut revoc)? {
                return Ok(Some(cert));
            }
        }
        Ok(None)
    }

    /// Get a list of all Revocations for a cert
    pub fn revocations_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(cert)
    }

    /// Get reason and creation time for a Revocation
    pub fn revocation_details(
        &self,
        revocation: &Revocation,
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
        self.db.get_conn().transaction::<_, anyhow::Error, _>(|| {
            let cert = self.db.get_cert_by_id(revoc.cert_id)?;

            if let Some(mut cert) = cert {
                let sig = Pgp::armored_to_signature(&revoc.revocation)?;
                let c = Pgp::armored_to_cert(&cert.pub_cert)?;

                let revocation: Packet = sig.into();
                let revoked = c.insert_packets(vec![revocation])?;

                cert.pub_cert = Pgp::cert_to_armored(&revoked)?;

                let mut revoc = revoc.clone();
                revoc.published = true;

                self.db.update_cert(&cert).context("Couldn't update Cert")?;

                self.db
                    .update_revocation(&revoc)
                    .context("Couldn't update Revocation")?;

                Ok(())
            } else {
                Err(anyhow::anyhow!("Couldn't find cert for apply_revocation"))
            }
        })
    }

    /// Get an armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Result<String> {
        Pgp::sig_to_armored(sig)
    }

    // -------- emails

    /// Get all Emails for a Cert
    pub fn emails_get(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<models::CertEmail>> {
        self.db.get_emails_by_cert(cert)
    }

    // -------- bridges

    /// Make regex for trust signature from domain-name
    fn domain_to_regex(domain: &str) -> Result<String> {
        // "other.org" => "<[^>]+[@.]other\\.org>$"
        // FIXME: does this imply "subdomain allowed"?

        // syntax check domain
        if !publicsuffix::Domain::has_valid_syntax(domain) {
            return Err(anyhow::anyhow!(
                "Parameter is not a valid domainname"
            ));
        }

        // transform domain to regex
        let escaped_domain =
            &domain.split('.').collect::<Vec<_>>().join("\\.");
        Ok(format!("<[^>]+[@.]{}>$", escaped_domain))
    }

    /// Create a new Bridge (between this OpenPGP CA and a remote OpenPGP
    /// CA instance)
    ///
    /// The result of this operation is a signed public key for the remote
    /// CA. Once this signature is published and available to OpenPGP
    /// CA users, the bridge is in effect.
    ///
    /// When `remote_email` or `remote_scope` are not set, they are derived
    /// from the User ID in the key_file
    pub fn bridge_new(
        &self,
        remote_key_file: &PathBuf,
        remote_email: Option<&str>,
        remote_scope: Option<&str>,
    ) -> Result<(models::Bridge, Fingerprint)> {
        let remote_ca_cert =
            Cert::from_file(remote_key_file).context("Failed to read key")?;

        let remote_uids: Vec<_> = remote_ca_cert.userids().collect();

        // expect exactly one User ID in remote CA key (otherwise fail)
        if remote_uids.len() != 1 {
            return Err(anyhow::anyhow!(
                "Expected exactly one User ID in remote CA Cert",
            ));
        }

        let remote_uid = remote_uids[0].userid();

        // derive an email and domain from the User ID in the remote cert
        let (remote_cert_email, remote_cert_domain) = {
            if let Some(remote_email) = remote_uid.email()? {
                let split: Vec<_> = remote_email.split('@').collect();

                // expect remote email address with localpart "openpgp-ca"
                if split.len() != 2 || split[0] != "openpgp-ca" {
                    return Err(anyhow::anyhow!(format!(
                        "Unexpected remote email {}",
                        remote_email
                    )));
                }

                let domain = split[1];
                (remote_email.to_owned(), domain.to_owned())
            } else {
                return Err(anyhow::anyhow!(
                    "Couldn't get email from remote CA Cert"
                ));
            }
        };

        let scope = match remote_scope {
            Some(scope) => {
                // if scope and domain don't match, warn/error?
                // (FIXME: error, unless --force parameter has been given?!)
                if scope != remote_cert_domain {
                    return Err(anyhow::anyhow!(
                        "scope and domain don't match, currently unsupported"
                    ));
                }

                scope
            }
            None => &remote_cert_domain,
        };

        let email = match remote_email {
            None => remote_cert_email,
            Some(email) => email.to_owned(),
        };

        let regex = Self::domain_to_regex(scope)?;

        let regexes = vec![regex];

        let bridged = Pgp::bridge_to_remote_ca(
            self.ca_get_cert()?,
            remote_ca_cert,
            regexes,
        )?;

        // FIXME: transaction

        // store new bridge in DB
        let (ca_db, _) =
            self.db.get_ca().context("Couldn't find CA")?.unwrap();

        let cert: models::Cert = self.db.add_cert(
            &Pgp::cert_to_armored(&bridged)?,
            &bridged.fingerprint().to_hex(),
            None,
        )?;

        let new_bridge = models::NewBridge {
            email: &email,
            scope,
            cert_id: cert.id,
            cas_id: ca_db.id,
        };

        Ok((self.db.insert_bridge(new_bridge)?, bridged.fingerprint()))
    }

    /// Create a revocation Certificate for a Bridge and apply it the our
    /// copy of the remote CA's public key.
    ///
    /// Both the revoked remote public key and the revocation cert are
    /// printed to stdout.
    pub fn bridge_revoke(&self, email: &str) -> Result<()> {
        let bridge = self.db.search_bridge(email)?;
        if bridge.is_none() {
            return Err(anyhow::anyhow!("bridge not found"));
        }

        let bridge = bridge.unwrap();

        let (_, ca_cert) = self.db.get_ca()?.unwrap();
        let ca_cert = Pgp::armored_to_cert(&ca_cert.priv_cert)?;

        if let Some(mut db_cert) = self.db.get_cert_by_id(bridge.cert_id)? {
            let bridge_pub = Pgp::armored_to_cert(&db_cert.pub_cert)?;

            // make sig to revoke bridge
            let (rev_cert, cert) = Pgp::bridge_revoke(&bridge_pub, &ca_cert)?;

            let revoc_cert_arm = &Pgp::sig_to_armored(&rev_cert)?;
            println!("revoc cert:\n{}", revoc_cert_arm);

            // save updated key (with revocation) to DB
            let revoked_arm = Pgp::cert_to_armored(&cert)?;
            println!("revoked remote key:\n{}", &revoked_arm);

            db_cert.pub_cert = revoked_arm;
            self.db.update_cert(&db_cert)?;

            Ok(())
        } else {
            Err(anyhow::anyhow!("no cert found for bridge"))
        }
    }

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

    // --------- wkd

    /// Export all user keys (that have a userid in `domain`) and the CA key
    /// into a wkd directory structure
    ///
    /// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08
    pub fn wkd_export(&self, domain: &str, path: &Path) -> Result<()> {
        use sequoia_net::wkd;

        let ca_cert = self.ca_get_cert()?;
        wkd::insert(&path, domain, None, &ca_cert)?;

        for cert in self.user_certs_get_all()? {
            // don't export to WKD if the cert is marked "delisted"
            if !cert.delisted {
                let c = Pgp::armored_to_cert(&cert.pub_cert)?;

                if Self::cert_has_uid_in_domain(&c, domain)? {
                    wkd::insert(&path, domain, None, &c)?;
                }
            }
        }

        Ok(())
    }

    // -------- update keys from public key sources

    /// Pull a key from WKD and merge any updates into our local version of
    /// this key
    pub fn update_from_wkd(&self, cert: &models::Cert) -> Result<()> {
        use sequoia_net::wkd;

        use tokio::runtime::Runtime;
        let mut rt = Runtime::new()?;

        let emails = self.emails_get(&cert)?;

        let mut merge = Pgp::armored_to_cert(&cert.pub_cert)?;

        for email in emails {
            let certs =
                rt.block_on(async move { wkd::get(&email.addr).await });

            for c in certs? {
                if c.fingerprint().to_hex() == cert.fingerprint {
                    merge = merge.merge_public(c)?;
                }
            }
        }

        let mut updated = cert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_cert(&updated)?;

        Ok(())
    }

    /// Pull a key from hagrid and merge any updates into our local version of
    /// this key
    pub fn update_from_hagrid(&self, cert: &models::Cert) -> Result<()> {
        use tokio::runtime::Runtime;
        let mut rt = Runtime::new()?;

        let mut merge = Pgp::armored_to_cert(&cert.pub_cert)?;

        // get key from hagrid
        let c = sequoia_core::Context::new()?;
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(&c)?;

        let f = (cert.fingerprint).parse::<Fingerprint>()?;
        let c =
            rt.block_on(async move { hagrid.get(&KeyID::from(f)).await })?;

        // update in DB
        merge = merge.merge_public(c)?;

        let mut updated = cert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_cert(&updated)?;

        Ok(())
    }

    // -------- helper functions

    pub fn print_cert_info(armored: &str) -> Result<()> {
        let c = Pgp::armored_to_cert(&armored)?;
        for uid in c.userids() {
            println!("User ID: {}", uid.userid());
        }
        println!("Fingerprint '{}'", c);
        Ok(())
    }

    /// Is any uid of this cert for an email address in "domain"?
    fn cert_has_uid_in_domain(c: &Cert, domain: &str) -> Result<bool> {
        for uid in c.userids() {
            // is any uid in domain
            let email = uid.email()?;
            if let Some(email) = email {
                let split: Vec<_> = email.split('@').collect();

                if split.len() != 2 {
                    return Err(anyhow::anyhow!("unexpected email format"));
                }

                if split[1] == domain {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get all trust sigs on User IDs in this Cert
    fn get_trust_sigs(c: &Cert) -> Result<Vec<Signature>> {
        Ok(Self::get_third_party_sigs(c)?
            .iter()
            .filter(|s| s.trust_signature().is_some())
            .cloned()
            .collect())
    }

    /// Get all third party sigs on User IDs in this Cert
    fn get_third_party_sigs(c: &Cert) -> Result<Vec<Signature>> {
        let mut res = Vec::new();
        let policy = StandardPolicy::new();

        for uid in c.userids() {
            let sigs =
                uid.with_policy(&policy, None)?.bundle().certifications();
            sigs.iter().for_each(|s| res.push(s.clone()));
        }

        Ok(res)
    }
}
