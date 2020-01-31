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

use std::env;
use std::time::Duration;

use publicsuffix::Domain;

use openpgp::packet::Signature;
use openpgp::parse::Parse;
use openpgp::{Cert, Fingerprint, KeyID, Packet};
use sequoia_openpgp as openpgp;

use crate::db::Db;
use crate::models;
use crate::pgp::Pgp;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

pub struct Ca {
    db: Db,
}

impl Ca {
    pub fn new(database: Option<&str>) -> Self {
        let db = if let Some(database) = database {
            Some(database.to_string())
        } else {
            let database = env::var("OPENPGP_CA_DB");
            if let Ok(database) = database {
                Some(database)
            } else {
                // load config from .env
                dotenv::dotenv().ok();

                // diesel naming convention for .env
                Some(env::var("DATABASE_URL").unwrap())
            }
        };

        let db = Db::new(db);
        db.migrations();

        Ca { db }
    }

    pub fn init(&self) {
        println!("Initializing!");

        // FIXME what should this do?
        unimplemented!();
    }

    // -------- CAs

    pub fn ca_new(&self, domainname: &str) -> Result<()> {
        if self.db.get_ca()?.is_some() {
            return Err(failure::err_msg(
                "ERROR: CA has already been created",
            ));
        }

        // domainname syntax check
        if !Domain::has_valid_syntax(domainname) {
            return Err(failure::err_msg(
                "Parameter is not a valid domainname",
            ));
        }

        let (cert, _) =
            Pgp::make_private_ca_cert(domainname, Some("OpenPGP CA"))?;

        let ca_key = &Pgp::priv_cert_to_armored(&cert)?;

        self.db.insert_ca(models::NewCa { domainname }, ca_key)?;

        Ok(())
    }

    pub fn get_ca(&self) -> Result<Option<(models::Ca, models::Cacert)>> {
        self.db.get_ca()
    }

    pub fn get_ca_cert(&self) -> Result<Cert> {
        match self.db.get_ca()? {
            Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.cert)?),
            None => panic!("get_domain_ca() failed"),
        }
    }

    pub fn show_cas(&self) -> Result<()> {
        let (ca, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?
            .unwrap();
        println!("\n{}\n\n{}", ca.domainname, ca_cert.cert);
        Ok(())
    }

    pub fn export_pubkey(&self) -> Result<String> {
        let (_, ca_cert) = self
            .db
            .get_ca()
            .context("failed to load CA from database")?
            .unwrap();

        let cert = Pgp::armored_to_cert(&ca_cert.cert)?;
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    /// get all tsig(s) in this Cert
    fn get_tsigs(c: &Cert) -> Vec<&Signature> {
        c.userids()
            .flat_map(|b| b.binding().certifications())
            .filter(|&s| s.trust_signature().is_some())
            .collect()
    }

    /// get all sig(s) in this Cert (including subkeys)
    /// FIXME: is this what we want?
    fn get_sigs(c: &Cert) -> Vec<&Signature> {
        c.userids()
            .flat_map(|b| b.binding().certifications())
            .chain(c.keys().flat_map(|s| s.binding().certifications()))
            .collect()
    }

    pub fn import_tsig(&self, key_file: &str) -> Result<()> {
        use diesel::prelude::*;
        self.db.get_conn().transaction::<_, failure::Error, _>(|| {
            let ca_cert = self.get_ca_cert().unwrap();

            let ca_cert_imported =
                Cert::from_file(key_file).context("Failed to read key")?;

            // make sure the keys have the same Fingerprint
            if ca_cert.fingerprint() != ca_cert_imported.fingerprint() {
                return Err(failure::err_msg(
                    "The imported cert has an unexpected Fingerprint",
                ));
            }

            // get the tsig(s) from import
            let tsigs = Self::get_tsigs(&ca_cert_imported);

            // add tsig(s) to our "own" version of the CA key
            let mut packets: Vec<Packet> = Vec::new();
            tsigs.iter().for_each(|&s| packets.push(s.clone().into()));

            let signed = ca_cert
                .merge_packets(packets)
                .context("merging tsigs into CA Key failed")?;

            // update in DB
            let (_, mut ca_cert) = self
                .db
                .get_ca()
                .context("failed to load CA from database")?
                .unwrap();

            ca_cert.cert = Pgp::priv_cert_to_armored(&signed)
                .context("failed to armor CA Cert")?;

            self.db
                .update_cacert(&ca_cert)
                .context("Update of CA Cert in DB failed")?;

            Ok(())
        })
    }

    // -------- users

    pub fn user_new(
        &mut self,
        name: Option<&str>,
        emails: &[&str],
    ) -> Result<()> {
        let ca_cert = self.get_ca_cert().unwrap();

        // make user key (signed by CA)
        let (user, revoc) =
            Pgp::make_user(emails, name).context("make_user failed")?;

        // sign user key with CA key
        let certified =
            Pgp::sign_user(&ca_cert, &user).context("sign_user failed")?;

        // user tsigns CA key
        let tsigned_ca = Pgp::tsign_ca(&ca_cert, &user)
            .context("failed: user tsigns CA")?;

        let tsigned_ca_armored = Pgp::priv_cert_to_armored(&tsigned_ca)?;

        let pub_key = &Pgp::cert_to_armored(&certified)?;
        let revoc = Pgp::sig_to_armored(&revoc)?;

        let res = self.db.add_usercert(
            name,
            (pub_key, &user.fingerprint().to_hex()),
            emails,
            &[revoc],
            Some(&tsigned_ca_armored),
            None,
        );

        if res.is_err() {
            eprint!("{:?}", res);
            return Err(failure::err_msg("Couldn't insert user"));
        }

        // the private key needs to be handed over to the user, print for now
        println!(
            "new user key for {}:\n{}",
            name.unwrap_or(""),
            &Pgp::priv_cert_to_armored(&certified)?
        );
        // --

        Ok(())
    }

    // update existing or create independent new usercert,
    // importing pub cert from file
    fn usercert_import_update_or_create(
        &self,
        key: &str,
        revoc: Option<&str>,
        name: Option<&str>,
        emails: &[&str],
        updates_id: Option<i32>,
    ) -> Result<()> {
        let user_cert = Pgp::armored_to_cert(&key)?;

        let existing =
            self.db.get_usercert(&user_cert.fingerprint().to_hex())?;

        // check if a usercert with this fingerprint already exists?
        if let Some(mut existing) = existing {
            // yes - update existing Usercert in DB

            assert!(
                updates_id.is_none() || Some(existing.id) == updates_id,
                "updates_id was specified, but is inconsistent for key update"
            );

            // set of email addresses should be the same
            let existing_emails: HashSet<_> = self
                .db
                .get_emails_by_usercert(&existing)?
                .iter()
                .map(|e| e.addr.to_owned())
                .collect();
            let emails: HashSet<_> =
                emails.iter().map(|&s| s.to_string()).collect();
            assert!(
                emails.eq(&existing_emails),
                "expecting the same set of email addresses on key update"
            );

            // this "update" workflow is not handling revocation certs for now
            assert!(
                revoc.is_none(),
                "not expecting a revocation cert on key update"
            );

            // merge existing and new public key, update in DB usercert
            let c1 = Pgp::armored_to_cert(&existing.pub_cert)?;

            let updated = c1.merge(user_cert)?;
            let armored = Pgp::cert_to_armored(&updated)?;

            existing.pub_cert = armored;
            self.db.update_usercert(&existing)?;
        } else {
            // no - this is a new usercert that we need to create in the DB

            let ca_cert = self.get_ca_cert().unwrap();

            // sign only the userids that have been specified
            let certified =
                Pgp::sign_user_emails(&ca_cert, &user_cert, emails)?;

            // use name from userids, if no name was passed
            let name = match name {
                Some(name) => Some(name.to_owned()),
                None => {
                    let userids: Vec<_> = user_cert.userids().collect();
                    if userids.len() == 1 {
                        let userid = &userids[0];
                        userid.userid().name()?
                    } else {
                        None
                    }
                }
            };

            // use emails from userids, if no emails were passed
            let emails = if !emails.is_empty() {
                emails.iter().map(|&s| s.to_owned()).collect()
            } else {
                let userids: Vec<_> = user_cert.userids().collect();
                let emails: Vec<String> = userids
                    .iter()
                    .map(|uid| uid.userid().email().unwrap_or(None).unwrap())
                    .collect();
                emails
            };

            // map Vec<String> -> Vec<&str>
            let emails: Vec<&str> = emails.iter().map(|s| &**s).collect();

            // load revocation certificate
            let mut revocs: Vec<String> = Vec::new();

            if let Some(rev) = revoc {
                revocs.push(rev.to_owned());
            }

            let pub_key = &Pgp::cert_to_armored(&certified)?;

            self.db.add_usercert(
                name.as_deref(),
                (pub_key, &certified.fingerprint().to_hex()),
                &emails[..],
                &revocs,
                None,
                updates_id,
            )?;
        }

        Ok(())
    }

    pub fn usercert_import(
        &self,
        key: &str,
        revoc: Option<&str>,
        name: Option<&str>,
        emails: &[&str],
    ) -> Result<()> {
        self.usercert_import_update_or_create(key, revoc, name, emails, None)
    }

    pub fn usercert_import_update(
        &self,
        key: &str,
        usercert: &models::Usercert,
    ) -> Result<()> {
        let emails = self.db.get_emails_by_usercert(usercert)?;
        let emails: Vec<&str> =
            emails.iter().map(|e| e.addr.as_str()).collect();

        let name = match &usercert.name {
            None => None,
            Some(n) => Some(n.as_str()),
        };

        self.usercert_import_update_or_create(
            key,
            None,
            name,
            &emails[..],
            Some(usercert.id),
        )
    }

    pub fn usercert_expiry(
        &self,
        days: u64,
    ) -> Result<HashMap<models::Usercert, (bool, Option<SystemTime>)>> {
        let mut map = HashMap::new();

        let days = Duration::new(60 * 60 * 24 * days, 0);
        let expiry_test = SystemTime::now().checked_add(days).unwrap();

        let usercerts = self
            .get_all_usercerts()
            .context("couldn't load usercerts")?;

        for usercert in usercerts {
            let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
            let exp = Pgp::get_expiry(&cert)?;
            let alive = cert.alive(expiry_test).is_ok();

            map.insert(usercert, (alive, exp));
        }

        Ok(map)
    }

    pub fn usercert_signatures(
        &self,
    ) -> Result<HashMap<models::Usercert, (bool, bool)>> {
        let mut map = HashMap::new();

        let usercerts = self
            .get_all_usercerts()
            .context("couldn't load usercerts")?;

        for usercert in usercerts {
            let sig_from_ca = self
                .check_ca_sig(&usercert)
                .context("Failed while checking CA sig")?;

            let tsig_on_ca = self
                .check_ca_has_tsig(&usercert)
                .context("Failed while checking tsig on CA")?;

            map.insert(usercert, (sig_from_ca, tsig_on_ca));
        }

        Ok(map)
    }

    pub fn add_revocation(&self, revoc_file: &str) -> Result<()> {
        let revoc_cert = Pgp::load_revocation_cert(Some(revoc_file))
            .context("Couldn't load revocation cert")?;

        let sig_fingerprint =
            &Pgp::get_revoc_fingerprint(&revoc_cert).to_hex();

        let cert = self.db.get_usercert(sig_fingerprint)?;

        match cert {
            None => Err(failure::err_msg(
                "couldn't find cert for this fingerprint",
            )),
            Some(c) => {
                let cert_fingerprint = &c.fingerprint;
                assert_eq!(sig_fingerprint, cert_fingerprint);

                // update sig in DB
                let armored = Pgp::sig_to_armored(&revoc_cert)
                    .context("couldn't armor revocation cert")?;

                self.db.add_revocation(&armored, &c)?;

                Ok(())
            }
        }
    }

    pub fn get_all_usercerts(&self) -> Result<Vec<models::Usercert>> {
        self.db.list_usercerts()
    }

    pub fn get_usercerts(&self, email: &str) -> Result<Vec<models::Usercert>> {
        self.db.get_usercerts(email)
    }

    pub fn get_revocations(
        &self,
        cert: &models::Usercert,
    ) -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(cert)
    }

    pub fn get_revocation_by_id(&self, id: i32) -> Result<models::Revocation> {
        if let Some(rev) = self.db.get_revocation_by_id(id)? {
            Ok(rev)
        } else {
            Err(failure::err_msg("no revocation found"))
        }
    }

    pub fn apply_revocation(&self, revoc: models::Revocation) -> Result<()> {
        use diesel::prelude::*;
        self.db.get_conn().transaction::<_, failure::Error, _>(|| {
            let usercert = self.db.get_usercert_by_id(revoc.usercert_id)?;

            if let Some(mut usercert) = usercert {
                let sig = Pgp::armored_to_signature(&revoc.revocation)?;
                let cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

                let revocation: Packet = sig.into();
                let revoked = cert.merge_packets(vec![revocation])?;

                usercert.pub_cert = Pgp::cert_to_armored(&revoked)?;

                let mut revoc = revoc.clone();
                revoc.published = true;

                println!("cert {:?}", usercert);

                self.db
                    .update_usercert(&usercert)
                    .context("Couldn't update Usercert")?;

                println!("y");

                self.db
                    .update_revocation(&revoc)
                    .context("Couldn't update Revocation")?;

                Ok(())
            } else {
                Err(failure::err_msg(
                    "Couldn't find usercert for apply_revocation",
                ))
            }
        })
    }

    pub fn get_emails(
        &self,
        usercert: &models::Usercert,
    ) -> Result<Vec<models::Email>> {
        self.db.get_emails_by_usercert(usercert)
    }

    pub fn check_ca_sig(&self, usercert: &models::Usercert) -> Result<bool> {
        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert)?;
        let sigs = Self::get_sigs(&user_cert);

        let ca = self.get_ca_cert()?;

        Ok(sigs
            .iter()
            .any(|&s| s.issuer_fingerprint().unwrap() == &ca.fingerprint()))
    }

    pub fn check_ca_has_tsig(
        &self,
        usercert: &models::Usercert,
    ) -> Result<bool> {
        let ca = self.get_ca_cert()?;
        let tsigs = Self::get_tsigs(&ca);

        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert)?;

        Ok(tsigs.iter().any(|&t| {
            t.issuer_fingerprint().unwrap() == &user_cert.fingerprint()
        }))
    }

    // -------- bridges

    // "other.org" => "<[^>]+[@.]other\\.org>$"
    fn domain_to_regex(domain: &str) -> Result<String> {
        // syntax check domain
        if !Domain::has_valid_syntax(domain) {
            return Err(failure::err_msg(
                "Parameter is not a valid domainname",
            ));
        }

        // transform domain to regex
        let mut regex = "<[^>]+[@.]".to_string();

        regex.push_str(&domain.split('.').collect::<Vec<_>>().join("\\."));

        regex.push_str(">$");

        Ok(regex)
    }

    /// when scope is not set, it is derived from the user_id in the key_file
    pub fn bridge_new(
        &self,
        key_file: &str,
        email: Option<&str>,
        scope: Option<&str>,
    ) -> Result<models::Bridge> {
        let remote_ca_cert =
            Cert::from_file(key_file).context("Failed to read key")?;

        // derive an email and domain from the user_id in the remote cert
        let (cert_email, cert_domain) = {
            let uids: Vec<_> = remote_ca_cert.userids().collect();
            assert_eq!(
                uids.len(),
                1,
                "Expected exactly one userid in remote CA Cert"
            );

            let remote_uid = uids[0].userid();
            let remote_email = remote_uid.email()?;

            assert!(
                remote_email.is_some(),
                "Couldn't get email from remote CA Cert"
            );

            let remote_email = remote_email.unwrap();

            let split: Vec<_> = remote_email.split('@').collect();
            assert_eq!(split.len(), 2);

            assert_eq!(split[0], "openpgp-ca");

            let domain: &str = split[1];
            (remote_email.to_owned(), domain.to_owned())
        };

        let scope = match scope {
            Some(scope) => {
                // if scope and domain don't match, warn/error?
                // (FIXME: unless --force parameter has been given?!)
                assert_eq!(scope, cert_domain);

                scope
            }
            None => &cert_domain,
        };

        let email = match email {
            None => cert_email,
            Some(email) => email.to_owned(),
        };

        let regex = Self::domain_to_regex(scope)?;

        let regexes = vec![regex];

        let ca_cert = self.get_ca_cert().unwrap();

        // expect exactly one userid in remote CA key (otherwise fail)
        assert_eq!(
            remote_ca_cert.userids().len(),
            1,
            "remote CA should have exactly one userid, but has {}",
            remote_ca_cert.userids().len()
        );

        let bridged =
            Pgp::bridge_to_remote_ca(&ca_cert, &remote_ca_cert, regexes)?;

        // store in DB
        let (ca_db, _) =
            self.db.get_ca().context("Couldn't find CA")?.unwrap();

        let pub_key = &Pgp::cert_to_armored(&bridged)?;

        let new_bridge = models::NewBridge {
            email: &email,
            scope,
            pub_key,
            cas_id: ca_db.id,
        };

        let bridge = self.db.insert_bridge(new_bridge)?;

        Ok(bridge)
    }

    pub fn bridge_revoke(&self, email: &str) -> Result<()> {
        let bridge = self.db.search_bridge(email)?;
        assert!(bridge.is_some(), "bridge not found");

        let mut bridge = bridge.unwrap();

        //        println!("bridge {:?}", &bridge.clone());
        //        let ca_id = bridge.clone().cas_id;

        let (_, ca_cert) = self.db.get_ca()?.unwrap();
        let ca_cert = Pgp::armored_to_cert(&ca_cert.cert)?;

        let bridge_pub = Pgp::armored_to_cert(&bridge.pub_key)?;

        // make sig to revoke bridge
        let (rev_cert, cert) = Pgp::bridge_revoke(&bridge_pub, &ca_cert)?;

        let revoc_cert_arm = &Pgp::sig_to_armored(&rev_cert)?;
        println!("revoc cert:\n{}", revoc_cert_arm);

        // save updated key (with revocation) to DB
        let revoked_arm = Pgp::cert_to_armored(&cert)?;
        println!("revoked remote key:\n{}", &revoked_arm);

        bridge.pub_key = revoked_arm;
        self.db.update_bridge(&bridge)?;

        Ok(())
    }

    pub fn get_bridges(&self) -> Result<Vec<models::Bridge>> {
        self.db.list_bridges()
    }

    /// export all user keys + CA key into a wkd directory structure
    /// https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08
    pub fn export_wkd(&self, domain: &str, path: &Path) -> Result<()> {
        extern crate sequoia_net;
        use sequoia_net::wkd;

        let ca_cert = Pgp::armored_to_cert(&self.export_pubkey()?)?;
        wkd::insert(&path, domain, None, &ca_cert)?;

        for uc in self.get_all_usercerts()? {
            let c = Pgp::armored_to_cert(&uc.pub_cert)?;
            wkd::insert(&path, domain, None, &c)?;
        }

        Ok(())
    }

    pub fn update_from_wkd(&self, usercert: &models::Usercert) -> Result<()> {
        use sequoia_net::wkd;
        use tokio_core::reactor::Core;

        let emails = self.get_emails(&usercert)?;

        let mut merge = Pgp::armored_to_cert(&usercert.pub_cert)?;

        for email in emails {
            let mut core = Core::new().unwrap();
            let certs = core.run(wkd::get(&email.addr)).unwrap();

            for cert in certs {
                if cert.fingerprint().to_hex() == usercert.fingerprint {
                    merge = merge.merge(cert)?;
                }
            }
        }

        let mut updated = usercert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_usercert(&updated)?;

        Ok(())
    }

    pub fn update_from_hagrid(
        &self,
        usercert: &models::Usercert,
    ) -> Result<()> {
        use tokio_core::reactor::Core;

        let mut merge = Pgp::armored_to_cert(&usercert.pub_cert)?;

        // get key from hagrid
        let c = sequoia_core::Context::new()?;
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(&c)?;

        let mut core = Core::new().unwrap();

        let f = Fingerprint::from_hex(&usercert.fingerprint)?;
        let cert = core.run(hagrid.get(&KeyID::from(f)))?;

        // update in DB
        merge = merge.merge(cert)?;

        let mut updated = usercert.clone();
        updated.pub_cert = Pgp::cert_to_armored(&merge)?;

        self.db.update_usercert(&updated)?;

        Ok(())
    }
}
