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

use sequoia_openpgp as openpgp;

use openpgp::Packet;
use openpgp::Cert;
use openpgp::armor;
use openpgp::types::{SignatureType, ReasonForRevocation};
use openpgp::crypto::KeyPair;
use openpgp::packet::{Signature, UserID};
use openpgp::packet::signature::Builder;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::cert;

use failure::{self, ResultExt};
use sequoia_openpgp::{KeyHandle, Fingerprint};
use std::time::Duration;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

pub struct Pgp {}

impl Pgp {
    /// Generate an encryption- and signing-capable key for a user.
    fn make_user_cert(emails: &[&str]) -> Result<(Cert, Signature)> {
        let mut builder = cert::CertBuilder::new()
            .add_storage_encryption_subkey()
            .add_transport_encryption_subkey()
            .add_signing_subkey();

        for &email in emails {
            builder = builder.add_userid(UserID::from(email));
        }


        Ok(builder.generate()?)
    }

    /// Generate a key for the CA.
    fn make_ca_cert(emails: Option<&[&str]>) -> Result<(Cert, Signature)> {
        let mut builder = cert::CertBuilder::new();

        // FIXME: should not be encryption capable
        // FIXME: should not have subkeys

        if let Some(emails) = emails {
            for &email in emails {
                builder = builder.add_userid(UserID::from(email));
            }
        }

        Ok(builder.generate()?)
    }


    /// make a private CA key
    pub fn make_private_ca_cert(ca_uids: &[&str]) -> Result<(Cert, Signature)> {
        Pgp::make_ca_cert(Some(&ca_uids.to_vec()))
    }

    /// make a user Cert with "emails" as UIDs (all UIDs get signed)
    pub fn make_user(emails: &[&str]) -> Result<(Cert, Signature)> {
        Pgp::make_user_cert(emails)
    }

    /// make a "public key" ascii-armored representation of a Cert
    pub fn cert_to_armored(certified: &Cert) -> Result<String> {
        let mut v = Vec::new();
        certified.armored().serialize(&mut v)
            .context("Cert serialize failed")?;

        Ok(String::from_utf8(v)?.to_string())
    }

    pub fn get_expiry(cert: &Cert) -> Option<Duration> {
        cert.primary_key_signature(None).unwrap().key_expiration_time()
    }

    /// make a "private key" ascii-armored representation of a Cert
    pub fn priv_cert_to_armored(cert: &Cert) -> Result<String> {
        let mut buffer = std::io::Cursor::new(vec![]);
        {
            let mut writer =
                armor::Writer::new(&mut buffer,
                                   armor::Kind::SecretKey,
                                   &[][..]).unwrap();

            cert.as_tsk().serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buffer.get_ref().to_vec())?.to_string())
    }

    /// make a Cert from an ascii armored key
    pub fn armored_to_cert(armored: &str) -> Cert {
        Cert::from_bytes(armored.as_bytes()).unwrap()
    }


    /// Load Revocation Cert from file
    pub fn load_revocation_cert(revoc_file: Option<&str>) -> Result<Signature> {
        if let Some(filename) = revoc_file {
            // handle optional revocation cert

            let pile = openpgp::PacketPile::from_file(filename)
                .context("Failed to read revocation cert")?;

            assert_eq!(pile.clone().into_children().len(), 1,
                       "expected exactly one packet in revocation cert");

            if let Packet::Signature(s) = pile.into_children().next().unwrap() {
                return Ok(s);
            }
        };
        Err(failure::err_msg("Couldn't load Signature from file"))
    }

    pub fn get_revoc_fingerprint(revoc_cert: &Signature) -> Fingerprint {
        let keyhandles = revoc_cert.get_issuers();
        let sig_fingerprints: Vec<_> = keyhandles.iter()
            .map(|keyhandle|
                if let KeyHandle::Fingerprint(fp) = keyhandle {
                    Some(fp)
                } else {
                    None
                })
            .filter(|fp| fp.is_some())
            .map(|fp| fp.unwrap())
            .collect();

        assert_eq!(sig_fingerprints.len(), 1,
                   "expected exactly one Fingerprint in revocation cert");
        sig_fingerprints[0].clone()
    }

    /// make an ascii-armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Result<String> {
        // maybe use:
        // https://docs.sequoia-pgp.org/sequoia_openpgp/serialize/trait.Serialize.html#method.export

        let mut buf = std::io::Cursor::new(vec![]);
        {
            let rev = Packet::Signature(sig.clone());

            let mut writer =
                armor::Writer::new(&mut buf,
                                   armor::Kind::Signature,
                                   &[][..]).unwrap();
            rev.serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buf.get_ref().to_vec())?.to_string())
    }

    /// user tsigns CA key
    pub fn tsign_ca(ca_cert: &Cert, user: &Cert) -> Result<Cert> {
        let mut cert_keys = Self::get_cert_keys(&user)
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        // create a TSIG for each UserID
        for ca_uidb in ca_cert.userids() {
            for signer in &mut cert_keys {
                let builder = Builder::new(SignatureType::GenericCertification)
                    .set_trust_signature(255, 120)?;


                let tsig = ca_uidb.userid().bind(signer,
                                                 ca_cert,
                                                 builder,
                                                 None)?;

                sigs.push(tsig.into());
            }
        }

        let signed = ca_cert.clone().merge_packets(sigs)?;

        Ok(signed)
    }

    /// add trust signature to the public key of a remote CA
    pub fn bridge_to_remote_ca(ca_cert: &Cert,
                               remote_ca_cert: &Cert,
                               scope_regexes: &[&str]) -> Result<Cert> {

        // FIXME: do we want to support a tsig without any scope regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid!
        let userid = remote_ca_cert.userids().next().unwrap().userid();


        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        let remote_pubkey = remote_ca_cert.primary();

        let mut packets: Vec<Packet> = Vec::new();

        // create one TSIG for each regex
        for &regex in scope_regexes {
            for signer in &mut cert_keys {
                let builder = Builder::new(SignatureType::GenericCertification)
                    .set_trust_signature(255, 120)?
                    .set_regular_expression(regex.as_bytes())?;

                let tsig = userid.bind(signer,
                                       remote_ca_cert,
                                       builder, None)?;

                packets.push(tsig.into());
            }
        }

        // FIXME: expiration?

        let signed = remote_ca_cert.clone().merge_packets(packets)?;

        Ok(signed)
    }

    pub fn bridge_revoke(remote_ca_cert: &Cert, ca_cert: &Cert)
                         -> Result<(Signature, Cert)> {
        // there should be exactly one userid!
        let userid = remote_ca_cert.userids().next().unwrap().userid();

        // set_trust_signature, set_regular_expression(s), expiration

        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        // the CA should have exactly one key that can certify
        assert_eq!(cert_keys.len(), 1);

        let signer = &mut cert_keys[0];

        let mut packets: Vec<Packet> = Vec::new();

        let revocation_sig =
            cert::UserIDRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::Unspecified,
                    b"removing OpenPGP CA bridge").unwrap()
                .build(signer, &remote_ca_cert, userid, None)?;

        packets.push(revocation_sig.clone().into());


        let revoked = remote_ca_cert.clone().merge_packets(packets)?;

        Ok((revocation_sig, revoked))
    }

    /// sign all userids of Cert with CA Cert
    pub fn sign_user(ca_cert: &Cert, user: &Cert) -> Result<Cert> {
        // sign Cert with CA key

        let mut cert_keys = Self::get_cert_keys(&ca_cert)
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        for uidb in user.userids() {
            for signer in &mut cert_keys {
                let uid = uidb.userid();

                let sig = uid.certify(signer, &user, None, None, None)?;

                sigs.push(sig.into());
            }
        }

        let certified = user.clone().merge_packets(sigs)?;

        Ok(certified)
    }

    pub fn sign_user_emails(ca_cert: &Cert, user_cert: &Cert, emails: &[&str]) -> Result<Cert> {
        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        let mut packets: Vec<Packet> = Vec::new();

        for uid in user_cert.userids() {
            for signer in &mut cert_keys {
                let userid = uid.userid();

                let uid_addr = userid.email_normalized()?.unwrap();

                // Sign this userid if email has been given for this import call
                if emails.contains(&uid_addr.as_str()) {
                    // certify this userid
                    let cert = userid.certify(signer,
                                              &user_cert,
                                              SignatureType::PositiveCertification,
                                              None, None)?;

                    packets.push(cert.into());
                }

                // FIXME: complain about emails that have been specified but
                // haven't been found in the userids
//            panic!("Email {} not found in the key", );
            }
        }

        let result = user_cert.clone().merge_packets(packets)?;
        Ok(result)
    }

    /// get all valid, certification capable keys with secret key material
    fn get_cert_keys(cert: &Cert) -> Result<Vec<KeyPair>> {
        let keys = cert.keys().alive().revoked(false).for_certification().secret();

        Ok(keys.filter_map(|ka|
            ka.key().clone().mark_parts_secret()
                .expect("mark_parts_secret failed")
                .into_keypair().ok()
        ).collect())
    }
}
