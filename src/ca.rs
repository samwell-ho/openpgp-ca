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

use sequoia_openpgp as openpgp;

use openpgp::TPK;
use openpgp::Packet;
use openpgp::parse::Parse;

use crate::db::Db;
use crate::pgp::Pgp;
use crate::models;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

pub struct Ca {
    db: Db,
}

impl Ca {
    pub fn new(database: Option<&str>) -> Self {
        let db = Db::new(database);

        db.migrations();

        Ca { db }
    }

    pub fn init(&self) {
        println!("Initializing!");

        // FIXME what should this do?
        unimplemented!();
    }


    // -------- CAs

    pub fn ca_new(&self, emails: &[&str]) -> Result<()> {
//        println!("make ca for email '{:?}'", emails);

        assert_eq!(emails.len(), 1,
                   "'ca new' expects exactly one email address");

        let (tpk, revoc) = Pgp::make_private_ca_key(emails)?;

        let email = emails[0].to_owned();
        let ca_key = &Pgp::priv_tpk_to_armored(&tpk)?;
        let revoc_cert = &Pgp::sig_to_armored(&revoc)?;

        self.db.insert_ca(models::NewCa { email, ca_key, revoc_cert })?;

//        println!("new CA key:\n{:#?}", tpk);

        Ok(())
    }

    pub fn get_ca_key(&self) -> Result<openpgp::TPK> {
        match self.db.get_ca()? {
            Some(ca) => {
                let ca_tpk = Pgp::armored_to_tpk(&ca.ca_key);
                println!("CA: {:#?}", ca_tpk);
                Ok(ca_tpk)
            }
            None => panic!("get_domain_ca() failed")
        }
    }

    pub fn show_cas(&self) {
        let ca = self.db.get_ca()
            .expect("failed to load CA from database");
        println!("{:#?}", ca);
    }

    pub fn export_pubkey(&self) {
        let ca = self.db.get_ca()
            .expect("failed to load CA from database");

        let tpk = Pgp::armored_to_tpk(&ca.unwrap().ca_key);
        let ca_pub = Pgp::tpk_to_armored(&tpk)
            .expect("failed to transform CA key to armored pubkey");

        println!("{}", ca_pub);
    }

    // -------- users

    pub fn user_new(&mut self, name: Option<&str>, emails: Option<&[&str]>) -> Result<()> {
        let ca_key = self.get_ca_key().unwrap();

        println!("new user: uids {:?}", emails);

        // make user key (signed by CA)
        let (user, revoc) =
            Pgp::make_user(emails).context("make_user_key failed")?;

        // sign user key with CA key
        let certified =
            Pgp::sign_user(&ca_key, &user).context("sign_user failed")?;

        println!("=== user_tpk certified {:#?}\n", certified);

        // user tsigns CA key
        let tsigned_ca =
            Pgp::tsign_ca(&ca_key, &user).context("failed: user tsigns CA")?;

        let tsigned_ca_armored = Pgp::priv_tpk_to_armored(&tsigned_ca)?;
        println!("updated armored CA key: {}", tsigned_ca_armored);

        // now write new data to DB
        let mut ca_db = self.db.get_ca().context("Couldn't \
                find CA")?.unwrap();

        // store updated CA TPK in DB
        ca_db.ca_key = tsigned_ca_armored;

        self.db.update_ca(&ca_db)?;

        // FIXME: the private key needs to be handed over to
        // the user -> print for now?
        let priv_key = &Pgp::priv_tpk_to_armored(&certified)?;
        println!("secret user key:\n{}", priv_key);
        // --

        let pub_key = &Pgp::tpk_to_armored(&certified)?;
        let revoc = Pgp::sig_to_armored(&revoc)?;

        let new_user = models::NewUser {
            name,
            pub_key,
            revoc_cert: Some(revoc),
            cas_id: ca_db.id,
        };

        let user_id = self.db.insert_user(new_user)?;
        for addr in emails.unwrap() {
            self.db.insert_email(models::NewEmail { addr, user_id })?;
        }

        Ok(())
    }

    pub fn user_import(&self, name: Option<&str>, emails: Option<&[&str]>,
                       key_file: &str, revoc_file: Option<&str>) -> Result<()> {
        let ca_key = self.get_ca_key().unwrap();

        let user_key = TPK::from_file(key_file)
            .expect("Failed to read key");

        // sign only the userids that have been specified
        let certified =
            match emails {
                Some(e) => Pgp::sign_user_emails(&ca_key, &user_key, e)?,
                None => user_key
            };

        // load revocation certificate
        let mut revoc_cert = None;

        if let Some(filename) = revoc_file {
            // handle optional revocation cert

            let pile = openpgp::PacketPile::from_file(filename)
                .expect("Failed to read revocation cert");

            assert_eq!(pile.clone().into_children().len(), 1,
                       "expected exactly one packet in revocation cert");

            if let Packet::Signature(s) = pile.into_children().next().unwrap() {
                // FIXME: check if this Signature fits with the tpk?

                revoc_cert = Some(Pgp::sig_to_armored(&s)?);
            }
        };

        // put in DB
        let ca_db = self.db.get_ca().context("Couldn't find CA")?
            .unwrap();

        let pub_key = &Pgp::tpk_to_armored(&certified)?;
        let new_user =
            models::NewUser { name, pub_key, revoc_cert, cas_id: ca_db.id };

        let user_id = self.db.insert_user(new_user)?;
        for email in emails.unwrap() {
            let new_email = models::NewEmail { addr: email, user_id };
            self.db.insert_email(new_email)?;
        }

        Ok(())
    }

    pub fn get_users(&self) -> Result<Vec<models::User>> {
        self.db.list_users()
    }

    pub fn list_users(&self) -> Result<()> {
        let users = self.get_users()?;
        for user in users {
            println!("#{} - Name: {:?}", user.id, user.name);

            let emails = self.db.get_emails(user)?;
            println!("  -> emails {:?}", emails);
        }

        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<Option<models::User>> {
        self.db.get_user(email)
    }

    // -------- bridges

    pub fn bridge_new(&self, name: &str, key_file: &str,
                      regexes: Option<&[&str]>) -> Result<()> {
        let ca_key = self.get_ca_key().unwrap();

        let remote_ca_key = openpgp::TPK::from_file(key_file)
            .expect("Failed to read key");

        // expect exactly one userid in remote CA key (otherwise fail)
        assert_eq!(remote_ca_key.userids().len(), 1,
                   "remote CA should have exactly one userid, but has {}",
                   remote_ca_key.userids().len());

        let bridged = Pgp::bridge_to_remote_ca(&ca_key, &remote_ca_key, regexes)?;

        // store in DB
        let ca_db = self.db.get_ca().context("Couldn't find CA")?
            .unwrap();

        let pub_key = &Pgp::tpk_to_armored(&bridged)?;

        let new_bridge = models::NewBridge {
            name,
            pub_key,
            cas_id:
            ca_db.id,
        };

        self.db.insert_bridge(new_bridge)?;

        Ok(())
    }

    pub fn bridge_revoke(&self, name: &str) -> Result<()> {
        let bridge = self.db.search_bridge(name)?;
        assert!(bridge.is_some(), "bridge not found");

        let mut bridge = bridge.unwrap();

//        println!("bridge {:?}", &bridge.clone());
//        let ca_id = bridge.clone().cas_id;

        let ca = self.db.get_ca()?.unwrap();
        let ca_key = Pgp::armored_to_tpk(&ca.ca_key);

        let bridge_pub = Pgp::armored_to_tpk(&bridge.pub_key);

        // make sig to revoke bridge
        let (rev_cert, rev_tpk) = Pgp::bridge_revoke(&bridge_pub, &ca_key)?;

        let revoc_cert_arm = &Pgp::sig_to_armored(&rev_cert)?;
        println!("revoc cert:\n{}", revoc_cert_arm);

        // save updated key (with revocation) to DB
        let revoked_arm = Pgp::tpk_to_armored(&rev_tpk)?;
        println!("revoked remote key:\n{}", &revoked_arm);

        bridge.pub_key = revoked_arm;
        self.db.update_bridge(&bridge)?;

        Ok(())
    }

    pub fn list_bridges(&self) -> Result<()> {
        let bridges = self.db.list_bridges()?;

        for bridge in bridges {
            println!("Bridge '{}':\n\n{}", bridge.name, bridge.pub_key);
        }

        Ok(())
    }
}