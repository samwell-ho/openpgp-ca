// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! OpenPGP CA as a library
//!
//! Example usage:
//! ```
//! # use openpgp_ca_lib::ca::OpenpgpCaUninit;
//! # use tempfile;
//! // all state of an OpenPGP CA instance is persisted in one SQLite database
//! let db_filename = "/tmp/openpgp-ca.sqlite";
//! # // for Doc-tests we need a random database filename
//! # let file = tempfile::NamedTempFile::new().unwrap();
//! # let db_filename = file.path().to_str().unwrap();
//!
//! // start a new OpenPGP CA instance (implicitly creates the database file)
//! let openpgp_ca_uninit = OpenpgpCaUninit::new(Some(db_filename)).expect("Failed to set up CA");
//!
//! // initialize the CA Admin (with domainname and a symbolic name)
//! let openpgp_ca = openpgp_ca_uninit
//!     .ca_init("example.org", Some("Example Org OpenPGP CA Key"))
//!     .unwrap();
//!
//! // create a new user, with all signatures
//! // (the private key is printed to stdout and needs to be manually
//! // processed from there)
//! openpgp_ca
//!     .user_new(Some(&"Alice"), &["alice@example.org"], None, false, false)
//!     .unwrap();
//! ```

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::offset::Utc;
use chrono::DateTime;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

use crate::backend::card::CardCa;
use crate::backend::{card, Backend};
use crate::bridge;
use crate::ca_secret::CaSec;
use crate::cert;
use crate::db::models;
use crate::db::OcaDb;
use crate::export;
use crate::pgp::Pgp;
use crate::revocation;
use crate::update;

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

    /// Get the Cert of the CA (without private key material).
    pub(crate) fn ca_get_cert_pub(&self) -> Result<Cert> {
        let (_, cacert) = self.db().get_ca()?;

        let cert = Pgp::to_cert(cacert.priv_cert.as_bytes())?;
        Ok(cert.strip_secret_key_material())
    }
}

/// A CA instance that has a database, but is (possibly) not initialized and doesn't
/// have a backend for private key operations yet.
pub struct OpenpgpCaUninit {
    db: Rc<OcaDb>,
    ca: Rc<DbCa>,
}

/// OpenpgpCa exposes the functionality of OpenPGP CA as a library
/// (the command line utility 'openpgp-ca' is built on top of this library)
pub struct OpenpgpCa {
    db: Rc<OcaDb>,

    ca: Rc<DbCa>,
    ca_secret: Rc<dyn CaSec>,
}

/// This struct models which User IDs of a Cert have (and which have not) been certified by a CA
pub struct CertificationStatus {
    pub certified: Vec<UserID>,
    pub uncertified: Vec<UserID>,
}

impl OpenpgpCaUninit {
    /// Instantiate a new OpenpgpCa object (with db, but without private key backend).
    ///
    /// This CA may be fully uninitialized and not be linked to a CA key yet.
    ///
    /// The SQLite backend filename can be configured:
    /// - explicitly via the db_url parameter, or
    /// - the environment variable OPENPGP_CA_DB.
    pub fn new(db_url: Option<&str>) -> Result<Self> {
        let db_url = if let Some(url) = db_url {
            url.to_owned()
        } else if let Ok(database) = env::var("OPENPGP_CA_DB") {
            database
        } else {
            return Err(anyhow::anyhow!("ERROR: no database configuration found"));
        };

        let db = Rc::new(OcaDb::new(&db_url)?);
        db.diesel_migrations_run();

        let dbca = Rc::new(DbCa::new(db.clone()));

        Ok(Self { db, ca: dbca })
    }

    /// Check if domainname is legal according to Mozilla's Public Suffix List
    fn check_domainname(domainname: &str) -> Result<()> {
        // domainname syntax check
        use addr::parser::DomainName;
        use addr::psl::List;
        if List.parse_domain_name(domainname).is_err() {
            return Err(anyhow::anyhow!("Invalid domainname: '{}'", domainname));
        }

        Ok(())
    }

    /// Init CA with softkey backend.
    ///
    /// This generates a new OpenPGP Key for the Admin role and stores the
    /// private Key in the OpenPGP CA database.
    ///
    /// `domainname` is the domain that this CA Admin is in charge of,
    /// `name` is a descriptive name for the CA Admin
    pub fn ca_init(self, domainname: &str, name: Option<&str>) -> Result<OpenpgpCa> {
        Self::check_domainname(domainname)?;
        let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

        self.db
            .transaction(|| self.ca.ca_init_softkey(domainname, &cert))?;

        self.init_from_db_state()
    }

    /// Init CA with OpenPGP card backend. Generate key material on the card.
    ///
    /// This assumes that:
    /// - all key slots on the card are currently empty
    /// - the PINs are set to their default values (User PIN is '123456', Admin PIN is '12345678')
    ///
    /// The User PIN is changed to a new, random 8-digit value and persisted in the CA database.
    ///
    /// The user is encouraged to change the Admin PIN to a different setting.
    pub fn ca_init_generate_on_card(
        self,
        ident: &str,
        domain: &str,
        name: Option<&str>,
    ) -> Result<OpenpgpCa> {
        // The CA database must be uninitialized!
        if self.db.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA database is already initialized"));
        }

        let email = format!("openpgp-ca@{}", domain);
        let uid = Pgp::ca_user_id(&email, name);
        let uid = String::from_utf8_lossy(uid.value()).to_string();

        // Generate key material on card, get the public key,
        // initialize the CA with these artifacts.
        let (ca_cert, user_pin) = card::generate_on_card(ident, uid)?;

        self.ca_init_card(ident, &user_pin, domain, &ca_cert)
    }

    pub fn ca_init_generate_on_host(
        self,
        ident: &str,
        domain: &str,
        name: Option<&str>,
    ) -> Result<(OpenpgpCa, String)> {
        // The CA database must be uninitialized!
        if self.db.is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA database is already initialized"));
        }

        // Generate a new CA private key
        let (ca_key, _) = Pgp::make_ca_cert(domain, name)?;

        // Import key material to card.
        let user_pin = card::import_to_card(ident, &ca_key)?;

        // Private key material will get stripped implicitly by ca_init_card()
        let ca = self.ca_init_card(ident, &user_pin, domain, &ca_key)?;

        // return private key (unencrypted)
        let key = Pgp::cert_to_armored_private_key(&ca_key)?;

        Ok((ca, key))
    }

    /// Import the CA's public key and use it with a pre-initialized OpenPGP card.
    pub fn ca_init_import_existing_card(
        self,
        card_ident: &str,
        user_pin: &str,
        domain: &str,
        ca_cert: &[u8],
    ) -> Result<OpenpgpCa> {
        let ca_cert = Cert::from_bytes(ca_cert).context("Cert::from_bytes failed")?;

        // Check if user-supplied PIN is accepted by the card
        card::verify_user_pin(card_ident, user_pin)?;

        // FIXME: is there a reason to add more sanity checks if the cert and the keys on the card
        // really correspond?
        // (could perform crypto operations on the card and test against cert?)

        self.ca_init_card(card_ident, user_pin, domain, &ca_cert)
    }

    /// Init with OpenPGP card backend
    fn ca_init_card(
        self,
        card_ident: &str,
        pin: &str,
        domainname: &str,
        ca_cert: &Cert,
    ) -> Result<OpenpgpCa> {
        Self::check_domainname(domainname)?;

        // Open a separate scope for database-access.
        //
        // Without this block, init_from_db_state() [below] gets stuck while trying to clone
        // the internal Rc<OcaDb> (FIXME: understand why this happens?!)
        {
            // The CA database must be uninitialized!
            if self.db.is_ca_initialized()? {
                return Err(anyhow::anyhow!("CA database is already initialized"));
            }

            // Open Smart Card
            let card = openpgp_card_pcsc::PcscBackend::open_by_ident(card_ident, None)?;
            let mut card = openpgp_card_sequoia::card::Card::new(card);
            let mut open = card.transaction()?;

            let fps = open.fingerprints()?;
            let sig = fps
                .signature()
                .context(format!("No Signing key on card {}", card_ident))?;

            let sig_fp = sig.to_string();

            let cardholder_name = open.cardholder_name()?;

            // Check that cardholder name is set to "OpenPGP CA".
            if cardholder_name != "OpenPGP CA" {
                return Err(anyhow::anyhow!(
                    "Unexpected cardholder name on OpenPGP card (expecting 'OpenPGP CA')"
                ));
            }

            // FIXME: make sure that the CA public key contains a User ID!
            // (So we can set the 'Signer's UserID' packet for easy WKD lookup of the CA cert)

            let pubkey = Pgp::cert_to_armored(ca_cert)
                .context("Failed to transform CA cert to armored pubkey")?;

            // CA pubkey and card signature key slot must match
            if ca_cert.fingerprint().to_hex() != sig_fp {
                return Err(anyhow::anyhow!(format!(
                    "Signature key slot on card {} doesn't match public key {}.",
                    sig_fp,
                    ca_cert.fingerprint().to_hex()
                )));
            }

            self.db.transaction(|| {
                CardCa::ca_init(&self.db, domainname, card_ident, pin, &pubkey, &sig_fp)
            })?;
        }

        self.init_from_db_state()
    }

    /// Initialize OpenpgpCa object - this assumes a backend has previously been configured.
    pub fn init_from_db_state(self) -> Result<OpenpgpCa> {
        // FIXME: ->  handle uninitialized (-> error?)

        // check database state of this CA
        let (ca, _) = self.db.get_ca()?;

        match Backend::from_config(ca.backend.as_deref())? {
            Backend::Softkey => Ok(OpenpgpCa {
                db: self.db,
                ca: self.ca.clone(),
                ca_secret: self.ca,
            }),
            Backend::Card(card) => {
                let ca_secret = Rc::new(CardCa::new(&card.ident, &card.user_pin, self.db.clone())?);

                Ok(OpenpgpCa {
                    db: self.db,
                    ca: self.ca,
                    ca_secret,
                })
            }
        }
    }
}

impl OpenpgpCa {
    pub fn db(&self) -> &OcaDb {
        &self.db
    }

    // -------- CA

    /// Get the CaSec implementation to run operations that need CA
    /// private key material.
    ///
    /// Print information about the created CA instance to stdout.
    pub(crate) fn secret(&self) -> &Rc<dyn CaSec> {
        &self.ca_secret
    }

    pub fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        self.ca_secret.ca_generate_revocations(output)
    }

    pub fn ca_import_tsig(&self, cert: &[u8]) -> Result<()> {
        self.db().transaction(|| self.db.ca_import_tsig(cert))
    }

    pub fn ca_get_cert_pub(&self) -> Result<Cert> {
        self.ca.ca_get_cert_pub()
    }

    /// Returns the public key of the CA as an armored String
    pub fn ca_get_pubkey_armored(&self) -> Result<String> {
        let cert = self.ca_get_cert_pub()?;
        let ca_pub =
            Pgp::cert_to_armored(&cert).context("Failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    pub fn get_ca_email(&self) -> Result<String> {
        self.ca.ca_email()
    }

    /// Get the domainname for this CA
    pub fn get_ca_domain(&self) -> Result<String> {
        let email = self.get_ca_email()?;
        let email_split: Vec<_> = email.split('@').collect();

        if email_split.len() == 2 {
            Ok(email_split[1].to_owned())
        } else {
            Err(anyhow::anyhow!("Failed to split domain from CA email"))
        }
    }

    /// Print information about the Ca to stdout.
    ///
    /// This shows the domainname, fingerprint and creation time of this OpenPGP CA instance.
    pub fn ca_show(&self) -> Result<()> {
        let (ca, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?;

        let cert = Cert::from_str(&ca_cert.priv_cert)?;

        let created = cert.primary_key().key().creation_time();
        let created: DateTime<Utc> = created.into();

        println!("    CA Domain: {}", ca.domainname);
        println!("  Fingerprint: {}", cert.fingerprint());
        println!("Creation time: {}", created.format("%F %T %Z"));

        let backend = Backend::from_config(ca.backend.as_deref())?;
        if backend != Backend::Softkey {
            println!("   CA Backend: {}", backend);
        }

        Ok(())
    }

    /// Print private key of the Ca to stdout.
    pub fn ca_print_private(&self) -> Result<()> {
        let (_, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?;
        println!("{}", ca_cert.priv_cert);
        Ok(())
    }

    /// Find all User IDs that have been certified by `cert_old` and re-certify them
    /// with the current CA key.
    ///
    /// This can be useful after CA key rotation: when the CA has a new key, `ca_re_certify` issues
    /// fresh certifications for all previously CA-certified user certs.
    pub fn ca_re_certify(&self, cert_old: &[u8], validity_days: u64) -> Result<()> {
        let cert_old = Pgp::to_cert(cert_old)?;

        self.db()
            .transaction(|| cert::certs_re_certify(self, cert_old, validity_days))
    }

    // -------- users / certs

    /// Get a list of all User Certs
    pub fn user_certs_get_all(&self) -> Result<Vec<models::Cert>> {
        let users = self.db.users_sorted_by_name()?;
        let mut user_certs = Vec::new();
        for user in users {
            user_certs.append(&mut self.db.certs_by_user(&user)?);
        }
        Ok(user_certs)
    }

    /// Which certs will be expired in 'days' days?
    ///
    /// If a cert is not "alive" now, it will not get returned as expiring
    /// (otherwise old/abandoned certs would clutter the results)
    pub fn certs_expired(&self, days: u64) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
        cert::certs_expired(self, days)
    }

    /// Check if this Cert has been certified by the CA Key, returns all
    /// certified User IDs
    pub fn cert_check_ca_sig(&self, cert: &models::Cert) -> Result<CertificationStatus> {
        cert::cert_check_ca_sig(self, cert).context("Failed while checking CA sig")
    }

    /// Check if this Cert has tsigned the CA Key
    pub fn cert_check_tsig_on_ca(&self, cert: &models::Cert) -> Result<bool> {
        cert::cert_check_tsig_on_ca(self, cert).context("Failed while checking tsig on CA")
    }

    /// Check all Certs for certifications from the CA. If a certification
    /// expires in less than `threshold_days` and it is not marked as
    /// 'inactive', make a new certification that is good for
    /// `validity_days` and update the Cert.
    pub fn certs_refresh_ca_certifications(
        &self,
        threshold_days: u64,
        validity_days: u64,
    ) -> Result<()> {
        self.db().transaction(|| {
            cert::certs_refresh_ca_certifications(self, threshold_days, validity_days)
        })
    }

    /// Create a new OpenPGP CA User.
    /// ("Centralized key creation workflow")
    ///
    /// This generates a fresh OpenPGP key for the new User.
    /// The private key is printed to stdout and NOT stored in OpenPGP CA.
    /// The public key material (Cert) is stored in the OpenPGP CA database.
    ///
    /// The CA Cert is trust-signed by this new user key and the user
    /// Cert is certified by the CA.
    pub fn user_new(
        &self,
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
        password: bool,
        output_format_minimal: bool,
    ) -> Result<()> {
        self.db().transaction(|| {
            cert::user_new(
                self,
                name,
                emails,
                duration_days,
                password,
                output_format_minimal,
            )
        })
    }

    /// Import an existing OpenPGP Cert (public key) as a new OpenPGP CA user.
    ///
    /// The `cert` parameter accepts the user's armored public key.
    ///
    /// User IDs that correspond to `emails` will be signed by the CA.
    ///
    /// A symbolic `name` and a list of `emails` for this User can
    /// optionally be supplied. If those are not set, emails are taken from
    /// the list of User IDs in the public key. If the key has exactly one
    /// User ID, the symbolic name is taken from that User ID.
    ///
    /// Optionally, revocation certificates can be supplied for storage in
    /// OpenPGP CA.
    pub fn cert_import_new(
        &self,
        cert: &[u8],
        revoc_certs: &[&[u8]],
        name: Option<&str>,
        emails: &[&str],
        duration_days: Option<u64>,
    ) -> Result<()> {
        self.db().transaction(|| {
            cert::cert_import_new(self, cert, revoc_certs, name, emails, duration_days)
        })
    }

    /// Update existing Cert in database (e.g. if the user has extended
    /// the expiry date)
    pub fn cert_import_update(&self, cert: &[u8]) -> Result<()> {
        self.db()
            .transaction(|| cert::cert_import_update(self, cert))
    }

    /// Get Cert by fingerprint.
    ///
    /// The fingerprint parameter is normalized (e.g. if it contains
    /// spaces, they will be filtered out).
    pub fn cert_get_by_fingerprint(&self, fingerprint: &str) -> Result<Option<models::Cert>> {
        self.db.cert_by_fp(&Pgp::normalize_fp(fingerprint)?)
    }

    /// Get a list of all Certs for one User
    pub fn get_certs_by_user(&self, user: &models::User) -> Result<Vec<models::Cert>> {
        self.db.certs_by_user(user)
    }

    /// Get a list of all Users, ordered by name
    pub fn users_get_all(&self) -> Result<Vec<models::User>> {
        self.db.users_sorted_by_name()
    }

    /// Get a list of the Certs that are associated with `email`
    pub fn certs_by_email(&self, email: &str) -> Result<Vec<models::Cert>> {
        self.db.certs_by_email(email)
    }

    /// Get database User(s) for database Cert
    pub fn cert_get_users(&self, cert: &models::Cert) -> Result<Option<models::User>> {
        self.db.user_by_cert(cert)
    }

    /// Get the user name that is associated with this Cert.
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

        let db_users = self.users_get_all()?;
        for db_user in &db_users {
            for db_cert in self.get_certs_by_user(db_user)? {
                let sigs_by_ca = self.cert_check_ca_sig(&db_cert)?;
                let tsig_on_ca = self.cert_check_tsig_on_ca(&db_cert)?;

                let sig_by_ca = !sigs_by_ca.certified.is_empty();

                if sig_by_ca && tsig_on_ca {
                    count_ok += 1;
                } else {
                    println!(
                        "No mutual certification for {}{}:",
                        db_cert.fingerprint,
                        db_user
                            .name
                            .as_deref()
                            .map(|s| format!(" ({})", s))
                            .unwrap_or_else(|| "".to_string()),
                    );

                    if !sig_by_ca {
                        println!("  No CA certification on any User ID");
                    }

                    if !tsig_on_ca {
                        println!("  Has not tsigned CA key.");
                    };

                    println!();
                }
            }
        }

        println!(
            "Checked {} user keys, {} of them have mutual certifications.",
            db_users.len(),
            count_ok
        );

        Ok(())
    }

    pub fn print_expiry_status(&self, exp_days: u64) -> Result<()> {
        let expiries = self.certs_expired(exp_days)?;

        if expiries.is_empty() {
            println!("No certificates will expire in the next {} days.", exp_days);
        } else {
            println!(
                "The following {} certificate{} will expire in the next {} days.",
                expiries.len(),
                if expiries.len() == 1 { "" } else { "s" },
                exp_days
            );
            println!();
        }

        for (db_cert, expiry) in expiries {
            let name = self.cert_get_name(&db_cert)?;
            println!("name {}, fingerprint {}", name, db_cert.fingerprint);

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
        for db_user in self.users_get_all()? {
            for db_cert in self.get_certs_by_user(&db_user)? {
                let sig_by_ca = self.cert_check_ca_sig(&db_cert)?;
                let tsig_on_ca = self.cert_check_tsig_on_ca(&db_cert)?;

                println!("OpenPGP certificate {}", db_cert.fingerprint);
                if let Some(name) = &db_user.name {
                    println!(" User '{}'", name);
                }

                if !sig_by_ca.certified.is_empty() {
                    println!(" Identities certified by this CA:");
                    for uid in sig_by_ca.certified {
                        println!(
                            " - '{} <{}>'",
                            uid.name()?.unwrap_or_else(|| "".to_string()),
                            uid.email()?.unwrap_or_else(|| "".to_string())
                        );
                    }
                }

                if tsig_on_ca {
                    println!(" Has trust-signed this CA");
                }

                let c = Pgp::to_cert(db_cert.pub_cert.as_bytes())?;

                if let Some(exp) = Pgp::get_expiry(&c)? {
                    let datetime: DateTime<Utc> = exp.into();
                    println!(" Expiration {}", datetime.format("%d/%m/%Y"));
                } else {
                    println!(" No expiration is set");
                }

                let revs = self.revocations_get(&db_cert)?;
                if !revs.is_empty() {
                    println!(" {} revocations available", revs.len());
                }

                if Pgp::is_possibly_revoked(&c) {
                    println!(" This certificate has (possibly) been REVOKED");
                }
                println!();
            }
        }

        Ok(())
    }

    // -------- revocations

    /// Get a list of all Revocations for a cert
    pub fn revocations_get(&self, cert: &models::Cert) -> Result<Vec<models::Revocation>> {
        self.db.revocations_by_cert(cert)
    }

    /// Add a revocation certificate to the OpenPGP CA database.
    ///
    /// The matching cert is looked up by issuer Fingerprint, if
    /// possible - or by exhaustive search otherwise.
    ///
    /// Verifies that applying the revocation cert can be validated by the
    /// cert. Only if this is successful is the revocation stored.
    pub fn revocation_add(&self, revoc_cert: &[u8]) -> Result<()> {
        self.db()
            .transaction(|| revocation::revocation_add(self, revoc_cert))
    }

    /// Add a revocation certificate to the OpenPGP CA database (from a file).
    pub fn revocation_add_from_file(&self, filename: &Path) -> Result<()> {
        let rev = std::fs::read(filename)?;

        self.db().transaction(|| self.revocation_add(&rev))
    }

    /// Get a Revocation by hash
    pub fn revocation_get_by_hash(&self, hash: &str) -> Result<models::Revocation> {
        if let Some(rev) = self.db.revocation_by_hash(hash)? {
            Ok(rev)
        } else {
            Err(anyhow::anyhow!("No revocation found for {}", hash))
        }
    }

    /// Apply a revocation.
    ///
    /// The revocation is merged into out copy of the OpenPGP Cert.
    pub fn revocation_apply(&self, revoc: models::Revocation) -> Result<()> {
        self.db()
            .transaction(|| revocation::revocation_apply(self, revoc))
    }

    /// Get reason and creation time for a Revocation
    pub fn revocation_details(
        revocation: &models::Revocation,
    ) -> Result<(String, Option<SystemTime>)> {
        let rev = Pgp::to_signature(revocation.revocation.as_bytes())?;

        let creation = rev.signature_creation_time();

        if let Some((code, reason)) = rev.reason_for_revocation() {
            let reason = String::from_utf8(reason.to_vec())?;
            Ok((format!("{} ({})", code, reason), creation))
        } else {
            Ok(("Revocation reason unknown".to_string(), creation))
        }
    }

    /// Get an armored representation of a revocation certificate
    pub fn revoc_to_armored(sig: &Signature) -> Result<String> {
        Pgp::revoc_to_armored(sig, None)
    }

    pub fn print_revocations(&self, email: &str) -> Result<()> {
        let certs = self.certs_by_email(email)?;
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
                    println!(" - revocation id {}: {} ({})", r.hash, reason, time);
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
    pub fn emails_get(&self, cert: &models::Cert) -> Result<Vec<models::CertEmail>> {
        self.db.emails_by_cert(cert)
    }

    /// Get all Emails
    pub fn get_emails_all(&self) -> Result<Vec<models::CertEmail>> {
        self.db.emails()
    }

    // --------- bridges

    /// Get a list of Bridges
    pub fn bridges_get(&self) -> Result<Vec<models::Bridge>> {
        self.db.list_bridges()
    }

    /// Get a specific Bridge
    pub fn bridges_search(&self, email: &str) -> Result<models::Bridge> {
        if let Some(bridge) = self.db.bridge_by_email(email)? {
            Ok(bridge)
        } else {
            Err(anyhow::anyhow!("Bridge not found"))
        }
    }

    pub fn add_bridge(
        &self,
        email: Option<&str>,
        key_file: &Path,
        scope: Option<&str>,
        unscoped: bool,
        commit: bool,
    ) -> Result<()> {
        if commit {
            self.db.transaction::<_, anyhow::Error, _>(|| {
                let (bridge, fingerprint) =
                    bridge::bridge_new(self, key_file, email, scope, unscoped)?;

                println!("Signed OpenPGP key for {} as bridge.\n", bridge.email);
                println!("The fingerprint of the remote CA key is");
                println!("{}\n", fingerprint);

                Ok(())
            })?;
        } else {
            println!("Bridge creation DRY RUN.");
            println!();

            println!(
                "Please verify that this is the correct fingerprint for the \
            remote CA admin before continuing:"
            );
            println!();

            let key = std::fs::read(key_file)?;
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
        self.db().transaction(|| bridge::bridge_revoke(self, email))
    }

    pub fn print_bridges(&self, email: Option<String>) -> Result<()> {
        let bridges = if let Some(email) = email {
            vec![self.bridges_search(&email)?]
        } else {
            self.bridges_get()?
        };

        for bridge in bridges {
            println!("Bridge to '{}'", bridge.email);
            if let Some(db_cert) = self.db.cert_by_id(bridge.cert_id)? {
                println!("{}", db_cert.pub_cert);
            }
            println!();
        }

        Ok(())
    }

    pub fn list_bridges(&self) -> Result<()> {
        self.bridges_get()?.iter().for_each(|bridge| {
            println!("Bridge to '{}', (scope: '{}')", bridge.email, bridge.scope)
        });
        Ok(())
    }

    // -------- export

    /// Export all user keys (that have a userid in `domain`) and the CA key
    /// into a wkd directory structure
    ///
    /// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08
    pub fn export_wkd(&self, domain: &str, path: &Path) -> Result<()> {
        export::wkd_export(self, domain, path)
    }

    /// Export the contents of a CA in Keylist format.
    ///
    /// https://code.firstlook.media/keylist-rfc-explainer
    ///
    /// `path`: filesystem path into which the exported keylist and signature
    /// files will be written.
    ///
    /// `signature_uri`: the https address from which the signature file will
    /// be retrievable
    ///
    /// `force`: by default, this fn fails if the files exist; when force is
    /// true, overwrite.
    pub fn export_keylist(&self, path: PathBuf, signature_uri: String, force: bool) -> Result<()> {
        export::export_keylist(self, path, signature_uri, force)
    }

    /// Export Certs from this CA into files, with filenames based on email
    /// addresses of user ids.
    pub fn export_certs_as_files(&self, email_filter: Option<String>, path: &str) -> Result<()> {
        export::export_certs_as_files(self, email_filter, path)
    }

    pub fn print_certring(&self, email_filter: Option<String>) -> Result<()> {
        export::print_certring(self, email_filter)
    }

    // -------- Update certs from public sources

    /// Pull updates for all certs from WKD and merge them into our local
    /// storage.
    pub fn update_from_wkd(&self) -> Result<()> {
        for c in self.user_certs_get_all()? {
            match self.db().transaction(|| update::update_from_wkd(self, &c)) {
                Ok(true) => {
                    println!("Got update for cert {}", c.fingerprint);
                }
                Ok(false) => {
                    println!("No changes for cert {}", c.fingerprint);
                }
                Err(e) => {
                    eprintln!("Failed to update cert {}: {}", c.fingerprint, e);
                }
            }
        }
        Ok(())
    }

    /// Update all certs from keyserver
    pub fn update_from_keyserver(&self) -> Result<()> {
        for c in self.user_certs_get_all()? {
            match self.update_from_hagrid(&c) {
                Ok(true) => {
                    println!("Got update for cert {}", c.fingerprint);
                }
                Ok(false) => {
                    println!("No changes for cert {}", c.fingerprint);
                }
                Err(e) => {
                    eprintln!("Failed to update cert {}: {}", c.fingerprint, e);
                }
            }
        }
        Ok(())
    }

    /// Pull updates for a cert from the hagrid keyserver
    /// (https://keys.openpgp.org/) and merge any updates into our local
    /// storage for this cert.
    ///
    /// Returns "true" if updated data was received, false if not.
    pub fn update_from_hagrid(&self, cert: &models::Cert) -> Result<bool> {
        self.db()
            .transaction(|| update::update_from_hagrid(self, cert))
    }
}
