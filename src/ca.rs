// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
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

use sequoia_openpgp as openpgp;

use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::Armorer;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::types::ReasonForRevocation;
use openpgp::KeyHandle;
use openpgp::{Cert, Fingerprint, KeyID, Packet};

use sequoia_net::Policy;

use openpgp_keylist::{Key, Keylist, Metadata};

use crate::db::Db;
use crate::models;
use crate::pgp::Pgp;

use diesel::prelude::*;

use crate::models::Revocation;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

// export filename of keylist
const KEYLIST_FILE: &str = "keylist.json";

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
    /// This is the OpenPGP Cert of the CA.
    pub fn ca_get_cert(&self) -> Result<Cert> {
        match self.db.get_ca()? {
            Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.priv_cert)?),
            _ => panic!("get_ca_cert() failed"),
        }
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
        let ca = self.ca_get_cert()?;

        let mut file = std::fs::File::create(output)?;

        // write informational header
        writeln!(
            &mut file,
            "This file contains revocation certificates for the OpenPGP CA \n\
            instance '{}'.",
            self.get_ca_email()?
        )?;
        writeln!(&mut file)?;

        let msg = r#"These revocations can be used to invalidate the CA's key.
This is useful e.g. if the (private) CA key gets compromised (i.e. available
to a third party), or when the CA key becomes inaccessible to you.

CAUTION: This file needs to be kept safe from third parties who could use 
the revocations to adversarially invalidate your CA certificate!
Keep in mind that an attacker can use these revocations to 
perform a denial of service attack on your CA at the most inconvenient 
moment. When a revocation certificate has been published for your CA, you 
will need to start over with a fresh CA key.

Please store this file appropriately, to avoid it becoming accessible to 
adversaries."#;

        writeln!(&mut file, "{}\n\n", msg)?;

        writeln!(
            &mut file,
            "For reference, the certificate of your CA is\n\n{}\n",
            Pgp::cert_to_armored(&ca)?
        )?;

        writeln!(
            &mut file,
            "Revocation certificates (ordered by 'creation time') follow:\n"
        )?;

        let now = SystemTime::now();
        let thirty_days = Duration::new(30 * 24 * 60 * 60, 0);

        let mut signer = ca
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        for i in 0..=120 {
            let t = now + i * thirty_days;

            let dt: DateTime<Utc> = t.into();
            let date = dt.format("%Y-%m-%d");

            let hard = CertRevocationBuilder::new()
                .set_signature_creation_time(t)?
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyCompromised,
                    b"Certificate has been compromised",
                )?
                .build(&mut signer, &ca, None)?;

            let header = vec![(
                "Comment".to_string(),
                format!(
                    "Hard revocation (certificate compromised) ({})",
                    date
                ),
            )];
            writeln!(
                &mut file,
                "{}\n",
                &Pgp::revoc_to_armored(&hard, Some(header))?
            )?;

            let soft = CertRevocationBuilder::new()
                .set_signature_creation_time(t)?
                .set_reason_for_revocation(
                    ReasonForRevocation::KeyRetired,
                    b"Certificate retired",
                )?
                .build(&mut signer, &ca, None)?;

            let header = vec![(
                "Comment".to_string(),
                format!("Soft revocation (certificate retired) ({})", date),
            )];
            writeln!(
                &mut file,
                "{}\n",
                &Pgp::revoc_to_armored(&soft, Some(header))?
            )?;
        }

        Ok(())
    }

    /// get the email of this CA
    pub fn get_ca_email(&self) -> Result<String> {
        let cert = self.ca_get_cert()?;
        let uids: Vec<_> = cert.userids().collect();

        if uids.len() != 1 {
            return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
        }

        let email = &uids[0].userid().email()?;

        if let Some(email) = email {
            Ok(email.clone())
        } else {
            Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
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
        let tsigned_ca = Pgp::tsign(ca_cert, &user_cert, pass.as_deref())
            .context("failed: user tsigns CA")?;

        let tsigned_ca_armored =
            Pgp::cert_to_armored_private_key(&tsigned_ca)?;

        let pub_key = &Pgp::cert_to_armored(&certified)?;
        let revoc = Pgp::revoc_to_armored(&revoc, None)?;

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
                "A cert with this fingerprint already exists in the DB"
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
    ///
    /// If a cert is not "alive" now, it will not get returned as expiring.
    /// (Otherwise old/abandoned certs would clutter the results)
    pub fn certs_expired(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Cert, Option<SystemTime>>> {
        let mut map = HashMap::new();

        let days = Duration::new(60 * 60 * 24 * days, 0);
        let expiry_test = SystemTime::now().checked_add(days).unwrap();

        let certs =
            self.user_certs_get_all().context("couldn't load certs")?;

        for cert in certs {
            let c = Pgp::armored_to_cert(&cert.pub_cert)?;

            // only consider (and thus potentially notify as "expiring") certs
            // that are alive now
            if c.with_policy(&StandardPolicy::new(), None)?
                .alive()
                .is_err()
            {
                continue;
            }

            let exp = Pgp::get_expiry(&c)?;
            let alive = c
                .with_policy(&StandardPolicy::new(), expiry_test)?
                .alive()
                .is_ok();

            if !alive {
                map.insert(cert, exp);
            }
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
    ) -> Result<(Vec<UserID>, bool)> {
        let sig_from_ca = self
            .cert_check_ca_sig(&cert)
            .context("Failed while checking CA sig")?;

        let tsig_on_ca = self
            .cert_check_tsig_on_ca(&cert)
            .context("Failed while checking tsig on CA")?;

        Ok((sig_from_ca, tsig_on_ca))
    }

    /// Check if this Cert has been signed by the CA Key
    pub fn cert_check_ca_sig(
        &self,
        cert: &models::Cert,
    ) -> Result<Vec<UserID>> {
        let c = Pgp::armored_to_cert(&cert.pub_cert)?;

        let ca = self.ca_get_cert()?;

        let mut res = Vec::new();
        let policy = StandardPolicy::new();

        for uid in c.userids() {
            let signed_by_ca = uid
                .clone()
                .with_policy(&policy, None)?
                .bundle()
                .certifications()
                .iter()
                .any(|s| {
                    s.issuer_fingerprints().any(|f| f == &ca.fingerprint())
                });

            if signed_by_ca {
                res.push(uid.userid().clone());
            }
        }

        Ok(res)
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
    pub fn armored_keyring_to_certs<D: AsRef<[u8]> + Send + Sync>(
        armored: &D,
    ) -> Result<Vec<Cert>> {
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

    /// Export Certs from this CA into files, with filenames based on email
    /// addresses of user ids.
    pub fn export_certs_as_files(
        &self,
        email_filter: Option<String>,
        path: Option<String>,
    ) -> Result<()> {
        if let Some(path) = path {
            // export to filesystem, individual files split by email

            // export CA cert
            if email_filter.is_none() {
                // add CA cert to output
                let ca_cert = self.ca_get_cert()?;

                std::fs::write(
                    path_append(
                        &path,
                        &format!("{}.asc", &self.get_ca_email()?),
                    )?,
                    Self::certs_to_armored(&[ca_cert])?,
                )?;
            }

            let emails = if let Some(email) = email_filter {
                vec![email]
            } else {
                self.get_emails_all()?
                    .iter()
                    .map(|ce| ce.addr.clone())
                    .collect()
            };

            for email in &emails {
                if let Ok(certs) = self.certs_get(email) {
                    if !certs.is_empty() {
                        let mut c: Vec<_> = vec![];
                        for cert in certs {
                            c.push(OpenpgpCa::armored_to_cert(
                                &cert.pub_cert,
                            )?);
                        }

                        std::fs::write(
                            path_append(&path, &format!("{}.asc", email))?,
                            Self::certs_to_armored(&c)?,
                        )?;
                    }
                } else {
                    println!("ERROR loading certs for email '{}'", email)
                };
            }
        } else {
            // write to stdout
            let certs = match email_filter {
                Some(email) => self.certs_get(&email)?,
                None => self.user_certs_get_all()?,
            };

            let mut c = Vec::new();
            for cert in certs {
                c.push(Self::cert_to_cert(&cert)?);
            }

            println!("{}", Self::certs_to_armored(&c)?);
        }

        Ok(())
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
                    let armored = Pgp::revoc_to_armored(&revoc_cert, None)
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

            let revoc_cert_arm = &Pgp::revoc_to_armored(&rev_cert, None)?;
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

    pub fn list_bridges(&self) -> Result<()> {
        self.bridges_get()?.iter().for_each(|bridge| {
            println!(
                "Bridge to '{}', (scope: '{}'",
                bridge.email, bridge.scope
            )
        });
        Ok(())
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

    pub fn add_bridge(
        &self,
        email: Option<&str>,
        key_file: &PathBuf,
        scope: Option<&str>,
        commit: bool,
    ) -> Result<()> {
        if commit {
            let (bridge, fingerprint) =
                self.bridge_new(key_file, email, scope)?;

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
            OpenpgpCa::print_cert_info(&key)?;

            println!();
            println!(
                "When you've confirmed that the remote key is correct, repeat \
            this command with the additional parameter '--commit' \
            to commit the OpenPGP CA bridge to the database."
            );
        }
        Ok(())
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

    // --------- keylist

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
        // filename of sigfile: last part of signature_uri
        let pos = &signature_uri.rfind('/').unwrap() + 1; //FIXME
        let sigfile_name = &signature_uri[pos..];

        // Start populating new Keylist
        let mut ukl = Keylist {
            metadata: Metadata {
                signature_uri: signature_uri.clone(),
                keyserver: None,
                comment: Some("Exported from OpenPGP CA".to_string()),
            },
            keys: vec![],
        };

        // .. add ca cert to Keylist ..
        let (ca, cacert) = self.ca_get()?.expect("failed to load CA");

        ukl.keys.push(Key {
            fingerprint: cacert.fingerprint,
            name: Some(format!("OpenPGP CA at {}", ca.domainname)),
            email: Some(self.get_ca_email()?),
            comment: None,
            keyserver: None,
        });

        // .. add all "signed-by-ca" certs to the list.
        for user in &self.users_get_all()? {
            for user_cert in self.get_certs_by_user(&user)? {
                // check if any user id of the cert has been certified by this ca (else skip)
                let (sig_from_ca, _) =
                    self.cert_check_certifications(&user_cert)?;
                if sig_from_ca.is_empty() {
                    continue;
                }

                // Create entries for each user id that the CA has certified
                for u in sig_from_ca {
                    if let Ok(Some(email)) = u.email() {
                        ukl.keys.push(Key {
                            fingerprint: user_cert.fingerprint.clone(),
                            name: user.name.clone(),
                            email: Some(email),
                            comment: None,
                            keyserver: None,
                        });
                    }
                }
            }
        }

        let signer = Box::new(|text: &str| self.sign_detached(text));

        // make a signed list object
        let skl = ukl.sign(signer)?;

        // Write keylist and signature to the filesystem
        let mut keylist = path.clone();
        keylist.push(KEYLIST_FILE);
        open_file(keylist, force)?
            .write_all(&skl.keylist.as_bytes().to_vec())?;

        let mut sigfile = path;
        sigfile.push(sigfile_name);
        open_file(sigfile, force)?.write_all(&skl.sig.as_bytes().to_vec())?;

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
        let mut hagrid =
            sequoia_net::KeyServer::keys_openpgp_org(Policy::Encrypted)?;

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

    pub fn tsign(
        signee: Cert,
        signer: &Cert,
        pass: Option<&str>,
    ) -> Result<Cert> {
        Pgp::tsign(signee, signer, pass)
    }

    pub fn sign_detached(&self, text: &str) -> Result<String> {
        let ca_cert = self.ca_get_cert()?;

        let signing_keypair = ca_cert
            .keys()
            .secret()
            .with_policy(&StandardPolicy::new(), None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message)
                // Customize the `Armorer` here.
                .build()?;

            let mut signer =
                Signer::new(message, signing_keypair).detached().build()?;

            // Write the data directly to the `Signer`.
            signer.write_all(text.as_bytes())?;
            signer.finalize()?;
        }

        Ok(std::str::from_utf8(&sink)?.to_string())
    }
}

// ------- util

fn open_file(name: PathBuf, overwrite: bool) -> std::io::Result<File> {
    if overwrite {
        File::create(name)
    } else {
        OpenOptions::new().write(true).create_new(true).open(name)
    }
}

// Append a (potentially adversarial) `filename` to a (presumed trustworthy)
// `path`.
//
// If `filename` contains suspicious chars, this fn returns an Err.
fn path_append(path: &str, filename: &str) -> Result<PathBuf> {
    // colon is a special char on windows (and illegal in emails)
    if filename.chars().any(std::path::is_separator)
        || filename.chars().any(|c| c == ':')
    {
        Err(anyhow::anyhow!(
            "filename contains special character - maybe a path traversal \
            attack? {}",
            filename
        ))
    } else {
        let mut pb = PathBuf::from_str(path)?;
        pb.push(filename);
        Ok(pb)
    }
}
