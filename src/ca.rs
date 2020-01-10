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

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::parse::Parse;
use openpgp::packet::Signature;

use crate::db::Db;
use crate::models;
use crate::pgp::Pgp;
use std::path::Path;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

pub struct Ca {
    db: Db,
}

impl Ca {
    pub fn new(database: Option<&str>) -> Self {
        let db =
            if database.is_some() {
                Some(database.unwrap().to_string())
            } else {
                let database = env::var("OPENPGP_CA_DB");
                if database.is_ok() { Some(database.unwrap()) } else {
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
        if let Some(_) = self.db.get_ca()? {
            return Err(failure::err_msg("ERROR: CA has already been created"));
        }

        // FIXME: use a better syntax check for domainname
        if domainname.contains("@") {
            return Err(failure::err_msg(
                "Parameter should be a domainname, not an email address"));
        }

        let (cert, _) = Pgp::make_private_ca_cert(domainname,
                                                  Some("OpenPGP CA"))?;

        let ca_key = &Pgp::priv_cert_to_armored(&cert)?;

        self.db.insert_ca(models::NewCa { domainname }, ca_key)?;

        Ok(())
    }

    pub fn get_ca(&self) -> Result<Option<(models::Ca, models::Cacert)>> {
        self.db.get_ca()
    }

    pub fn get_ca_cert(&self) -> Result<Cert> {
        match self.db.get_ca()? {
            Some((_, cert)) => {
                Ok(Pgp::armored_to_cert(&cert.cert))
            }
            None => panic!("get_domain_ca() failed")
        }
    }

    pub fn show_cas(&self) -> Result<()> {
        let (ca, ca_cert) = self.db.get_ca()
            .context("failed to load CA from database")?.unwrap();
        println!("\n{}\n\n{}", ca.domainname, ca_cert.cert);
        Ok(())
    }

    pub fn export_pubkey(&self) -> Result<String> {
        let (_, ca_cert) = self.db.get_ca()
            .context("failed to load CA from database")?.unwrap();

        let cert = Pgp::armored_to_cert(&ca_cert.cert);
        let ca_pub = Pgp::cert_to_armored(&cert)
            .context("failed to transform CA key to armored pubkey")?;

        Ok(ca_pub)
    }

    /// get all tsig(s) in this Cert
    fn get_tsigs(c: &Cert) -> Vec<&Signature> {
        c.userids()
            .flat_map(|b| b.certifications())
            .filter(|&s| s.trust_signature().is_some())
            .collect()
    }

    /// get all sig(s) in this Cert (including subkeys)
    /// FIXME: is this what we want?
    fn get_sigs(c: &Cert) -> Vec<&Signature> {
        c.userids()
            .flat_map(|b| b.certifications())
            .chain(c.subkeys().flat_map(|s| s.certifications()))
            .collect()
    }

    pub fn import_tsig(&self, key_file: &str) -> Result<()> {
        let ca_cert = self.get_ca_cert().unwrap();

        let ca_cert_imported = Cert::from_file(key_file)
            .context("Failed to read key")?;

        // make sure the keys have the same KeyID
        if ca_cert.keyid() != ca_cert_imported.keyid() {
            return Err(failure::err_msg("The imported key has an \
            unexpected keyid"));
        }

        // get the tsig(s) from import
        let tsigs = Self::get_tsigs(&ca_cert_imported);

        // add tsig(s) to our "own" version of the CA key
        let mut packets: Vec<Packet> = Vec::new();
        tsigs.iter().for_each(|&s| packets.push(s.clone().into()));

        let signed = ca_cert.merge_packets(packets)
            .context("merging tsigs into CA Key failed")?;

        // update in DB
        let (_, mut ca_cert) = self.db.get_ca()
            .context("failed to load CA from database")?
            .unwrap();

        ca_cert.cert = Pgp::priv_cert_to_armored(&signed)
            .context("failed to armor CA Cert")?;

        self.db.update_cacert(&ca_cert)
            .context("Update of CA Cert in DB failed")?;

        Ok(())
    }

    // -------- users

    pub fn user_new(&mut self, name: Option<&str>, emails: &[&str]) -> Result<()> {
        let ca_cert = self.get_ca_cert().unwrap();

        // make user key (signed by CA)
        let (user, revoc) =
            Pgp::make_user(emails, name).context("make_user failed")?;

        // sign user key with CA key
        let certified =
            Pgp::sign_user(&ca_cert, &user).context("sign_user failed")?;

        // user tsigns CA key
        let tsigned_ca =
            Pgp::tsign_ca(&ca_cert, &user).context("failed: user tsigns CA")?;

        let tsigned_ca_armored = Pgp::priv_cert_to_armored(&tsigned_ca)?;


        let pub_key = &Pgp::cert_to_armored(&certified)?;
        let revoc = Pgp::sig_to_armored(&revoc)?;

        let res = self.db.new_usercert(name, pub_key,
                                       &user.fingerprint().to_hex(),
                                       emails, &vec![revoc],
                                       Some(&tsigned_ca_armored));

        if res.is_err() {
            eprint!("{:?}", res);
            return Err(failure::err_msg("Couldn't insert user"));
        }

        // FIXME: the private key needs to be handed over to
        // the user -> print for now?
        let priv_key = &Pgp::priv_cert_to_armored(&certified)?;
        println!("new user key for {}:\n{}", name.unwrap_or(""), priv_key);
        // --

        Ok(())
    }

    pub fn user_import(&self, name: Option<&str>, emails: &[&str],
                       key_file: &str, revoc_file: Option<&str>) -> Result<()> {
        let ca_cert = self.get_ca_cert().unwrap();

        let user_cert = Cert::from_file(key_file)
            .context("Failed to read key")?;

        // sign only the userids that have been specified
        let certified =
            Pgp::sign_user_emails(&ca_cert, &user_cert, emails)?;


        // load revocation certificate
        let mut revoc: Vec<String> = Vec::new();

        if let Ok(rev) = Pgp::load_revocation_cert(revoc_file) {
            revoc.push(Pgp::sig_to_armored(&rev)?);
        }

        let pub_key = &Pgp::cert_to_armored(&certified)?;
        self.db.new_usercert(name, pub_key,
                             &certified.fingerprint().to_hex(),
                             emails, &revoc, None)?;

        Ok(())
    }


    pub fn add_revocation(&self, revoc_file: &str) -> Result<()> {
        let revoc_cert = Pgp::load_revocation_cert(Some(revoc_file))
            .context("Couldn't load revocation cert")?;

        let sig_fingerprint =
            &Pgp::get_revoc_fingerprint(&revoc_cert).to_hex();

        let cert = self.db.get_usercert(sig_fingerprint)?;

        match cert {
            None => Err(failure::err_msg("couldn't find cert for this fingerprint")),
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

    pub fn get_usercerts(&self, email: &str)
                         -> Result<Vec<models::Usercert>> {
        self.db.get_usercerts(email)
    }

    pub fn get_revocations(&self, cert: &models::Usercert)
                           -> Result<Vec<models::Revocation>> {
        self.db.get_revocations(cert)
    }

    pub fn get_emails(&self, usercert: &models::Usercert)
                      -> Result<Vec<models::Email>> {
        self.db.get_emails_by_usercert(usercert)
    }

    pub fn check_ca_sig(&self, usercert: &models::Usercert) -> Result<bool> {
        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert);
        let sigs = Self::get_sigs(&user_cert);

        let ca = self.get_ca_cert()?;

        Ok(sigs.iter()
            .any(|&s| s.issuer_fingerprint().unwrap() == &ca.fingerprint()))
    }

    pub fn check_ca_has_tsig(&self, usercert: &models::Usercert)
                             -> Result<bool> {
        let ca = self.get_ca_cert()?;
        let tsigs = Self::get_tsigs(&ca);


        let user_cert = Pgp::armored_to_cert(&usercert.pub_cert);

        Ok(tsigs.iter()
            .any(|&t| t.issuer_fingerprint().unwrap()
                == &user_cert.fingerprint()))
    }

    // -------- bridges

    // "other.org" => "<[^>]+[@.]other\\.org>$"
    fn domain_to_regex(domain: &str) -> Result<String> {

        // FIXME: check if domain String has the expected format
        // ...

        // transform domain to regex
        let mut regex = "<[^>]+[@.]".to_string();

        regex.push_str(&domain
            .split(".")
            .collect::<Vec<_>>()
            .join("\\."));

        regex.push_str(">$");

        Ok(regex)
    }

    /// when scope is not set, it is derived from the user_id in the key_file
    pub fn bridge_new(&self, key_file: &str,
                      email: Option<&str>, scope: Option<&str>)
                      -> Result<models::Bridge> {
        let remote_ca_cert = Cert::from_file(key_file)
            .context("Failed to read key")?;

        let (cert_email, cert_domain) = {
            let uids: Vec<_> = remote_ca_cert.userids().collect();
            assert_eq!(uids.len(), 1,
                       "Expected exactly one userid in remote CA Cert");

            let remote_uid = uids[0].userid();
            let remote_email = remote_uid.email()?;

            assert!(remote_email.is_some(),
                    "Couldn't get email from remote CA Cert");

            let remote_email = remote_email.unwrap();

            let split: Vec<_> = remote_email.split("@").collect();
            assert_eq!(split.len(), 2);

            assert_eq!(split[0], "openpgp-ca");

            let domain: &str = split[1];
            (remote_email.to_owned(), domain.to_owned())
        };

        let scope = match scope {
            Some(scope) => {
                // FIXME: if scope and domain don't match, warn/error?
                // (... unless --force parameter has been given?!)

                scope
            }
            None => &cert_domain
        };

        let email = match email {
            None => cert_email,
            Some(email) => email.to_owned()
        };

        let regex = Self::domain_to_regex(scope)?;

        let regexes = vec![regex];

        let ca_cert = self.get_ca_cert().unwrap();

        // expect exactly one userid in remote CA key (otherwise fail)
        assert_eq!(remote_ca_cert.userids().len(), 1,
                   "remote CA should have exactly one userid, but has {}",
                   remote_ca_cert.userids().len());

        let bridged = Pgp::bridge_to_remote_ca(&ca_cert, &remote_ca_cert,
                                               regexes)?;

        // store in DB
        let (ca_db, _) =
            self.db.get_ca().context("Couldn't find CA")?
                .unwrap();

        let pub_key = &Pgp::cert_to_armored(&bridged)?;

        let new_bridge =
            models::NewBridge {
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
        let ca_cert = Pgp::armored_to_cert(&ca_cert.cert);

        let bridge_pub = Pgp::armored_to_cert(&bridge.pub_key);

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

        let ca_cert = Pgp::armored_to_cert(&self.export_pubkey()?);
        wkd::insert(&path, domain, None, &ca_cert)?;

        for uc in self.get_all_usercerts()? {
            let c = Pgp::armored_to_cert(&uc.pub_cert);
            wkd::insert(&path, domain, None, &c)?;
        }

        Ok(())
    }
}