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

use openpgp::armor;
use openpgp::cert;
use openpgp::cert::components::Amalgamation;
use openpgp::cert::ValidKeyIter;
use openpgp::crypto::KeyPair;
use openpgp::packet::key::SecretParts;
use openpgp::packet::signature;
use openpgp::packet::{Signature, UserID};
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::{HashAlgorithm, KeyFlags};
use openpgp::types::{ReasonForRevocation, SignatureType};
use openpgp::{Cert, Fingerprint, KeyHandle, Packet};

use std::time::SystemTime;

use failure::{self, Fallible, ResultExt};

pub struct Pgp {}

impl Pgp {
    fn user_id(email: &str, name: Option<&str>) -> UserID {
        match name {
            Some(name) => UserID::from(format!("{} <{}>", name, email)),
            None => UserID::from(format!("<{}>", email)),
        }
    }

    /// make a private CA key
    pub fn make_ca_cert(
        domainname: &str,
        name: Option<&str>,
    ) -> Fallible<(Cert, Signature)> {
        // FIXME: should not be encryption capable (?)
        // FIXME: should not have subkeys

        // Generate a Cert, and create a keypair from the primary key.
        let (cert, sig) = cert::CertBuilder::new()
            .add_signing_subkey()
            // FIXME: set expiration from CLI
            // std::time::Duration::new(123456, 0)
            .set_expiration(None)
            .generate()?;

        let mut keypair = cert
            .primary_key()
            .key()
            .clone()
            .mark_parts_secret()?
            .into_keypair()?;

        // Generate a userid and a binding signature.
        let email = "openpgp-ca@".to_owned() + domainname;
        let userid = Self::user_id(&email, name);

        let direct_key_sig =
            cert.primary_key().policy(None).unwrap().binding_signature();
        let builder = signature::Builder::from(direct_key_sig.clone())
            .set_type(SignatureType::PositiveCertification)
            .set_key_flags(&KeyFlags::empty().set_certification(true))?
            // notation: "openpgp-ca:domain=domain1;domain2"
            .add_notation(
                "openpgp-ca",
                ("domain=".to_owned() + domainname).as_bytes(),
                signature::subpacket::NotationDataFlags::default()
                    .set_human_readable(true),
                false,
            )?;
        let binding = userid.bind(&mut keypair, &cert, builder)?;

        // Now merge the userid and binding signature into the Cert.
        let cert = cert.merge_packets(vec![userid.into(), binding.into()])?;

        Ok((cert, sig))
    }

    /// Makes a user Cert with "emails" as UIDs.
    pub fn make_user_cert(
        emails: &[&str],
        name: Option<&str>,
    ) -> Fallible<(Cert, Signature)> {
        let mut builder = cert::CertBuilder::new()
            .add_subkey(
                KeyFlags::default()
                    .set_transport_encryption(true)
                    .set_storage_encryption(true),
                None,
            )
            .add_signing_subkey();

        for email in emails {
            builder = builder.add_userid(Self::user_id(&email, name));
        }

        Ok(builder.generate()?)
    }

    /// make a "public key" ascii-armored representation of a Cert
    pub fn cert_to_armored(cert: &Cert) -> Fallible<String> {
        // FIXME: currently sequoia bug, but use this later:
        //    let v = cert.armored().to_vec().context("Cert serialize failed")?;

        let mut v = Vec::new();
        cert.armored().serialize(&mut v)?;

        Ok(String::from_utf8(v)?)
    }

    /// make a "private key" ascii-armored representation of a Cert
    pub fn priv_cert_to_armored(cert: &Cert) -> Fallible<String> {
        let mut buffer = vec![];
        {
            let headers = cert.armor_headers();
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let mut writer = armor::Writer::new(
                &mut buffer,
                armor::Kind::SecretKey,
                &headers,
            )
            .unwrap();

            cert.as_tsk().serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buffer)?)
    }

    /// make a Cert from an ascii armored key
    pub fn armored_to_cert(armored: &str) -> Fallible<Cert> {
        let cert =
            Cert::from_bytes(armored).context("Cert::from_bytes failed")?;

        Ok(cert)
    }

    /// make a Signature from an ascii armored signature
    pub fn armored_to_signature(armored: &str) -> Fallible<Signature> {
        let p = openpgp::Packet::from_bytes(armored)
            .context("Input could not be parsed")?;

        if let Packet::Signature(s) = p {
            Ok(s)
        } else {
            Err(failure::err_msg("Couldn't convert to Signature"))
        }
    }

    /// make an ascii-armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Fallible<String> {
        let mut buf = vec![];
        {
            let rev = Packet::Signature(sig.clone());

            let mut writer =
                armor::Writer::new(&mut buf, armor::Kind::Signature, &[][..])
                    .unwrap();
            rev.serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buf)?)
    }

    /// get expiration of cert as SystemTime
    pub fn get_expiry(cert: &Cert) -> Fallible<Option<SystemTime>> {
        let primary = cert.primary_key().policy(None)?;
        if let Some(duration) = primary.key_expiration_time() {
            let creation = primary.creation_time();
            Ok(creation.checked_add(duration))
        } else {
            Ok(None)
        }
    }

    /// Load Revocation Cert from file
    pub fn load_revocation_cert(
        revoc_file: Option<&str>,
    ) -> Fallible<Signature> {
        if let Some(filename) = revoc_file {
            let p = openpgp::Packet::from_file(filename)
                .context("Input could not be parsed")?;

            if let Packet::Signature(s) = p {
                return Ok(s);
            } else {
                return Err(failure::err_msg(
                    "Couldn't convert to revocation",
                ));
            }
        };
        Err(failure::err_msg("Couldn't load revocation from file"))
    }

    pub fn get_revoc_fingerprint(revoc_cert: &Signature) -> Fingerprint {
        let keyhandles = revoc_cert.get_issuers();
        let sig_fingerprints: Vec<_> = keyhandles
            .iter()
            .map(|keyhandle| {
                if let KeyHandle::Fingerprint(fp) = keyhandle {
                    Some(fp)
                } else {
                    None
                }
            })
            .filter(|fp| fp.is_some())
            .map(|fp| fp.unwrap())
            .collect();

        assert_eq!(
            sig_fingerprints.len(),
            1,
            "expected exactly one Fingerprint in revocation cert"
        );
        sig_fingerprints[0].clone()
    }

    /// user tsigns CA key
    pub fn tsign_ca(ca_cert: Cert, user: &Cert) -> Fallible<Cert> {
        let mut cert_keys = Self::get_cert_keys(&user)
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        // create a TSIG for each UserID
        for ca_uidb in ca_cert.userids() {
            for signer in &mut cert_keys {
                let builder = signature::Builder::new(
                    SignatureType::GenericCertification,
                )
                .set_trust_signature(255, 120)?;

                let tsig = ca_uidb.userid().bind(signer, &ca_cert, builder)?;
                sigs.push(tsig.into());
            }
        }

        let signed = ca_cert.merge_packets(sigs)?;

        Ok(signed)
    }

    /// add trust signature to the public key of a remote CA
    pub fn bridge_to_remote_ca(
        ca_cert: Cert,
        remote_ca_cert: Cert,
        scope_regexes: Vec<String>,
    ) -> Fallible<Cert> {
        // FIXME: do we want to support a tsig without any scope regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid
        assert_eq!(
            remote_ca_cert.userids().len(),
            1,
            "expect CA cert to have exactly one user_id"
        );
        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        let mut packets: Vec<Packet> = Vec::new();

        // create one TSIG for each regex
        for regex in scope_regexes {
            for signer in &mut cert_keys {
                let builder = signature::Builder::new(
                    SignatureType::GenericCertification,
                )
                .set_trust_signature(255, 120)?
                .set_regular_expression(regex.as_bytes())?;

                let tsig = userid.bind(signer, &remote_ca_cert, builder)?;

                packets.push(tsig.into());
            }
        }

        // FIXME: expiration?

        let signed = remote_ca_cert.merge_packets(packets)?;

        Ok(signed)
    }

    // FIXME: justus thinks this might not be supported by implementations
    pub fn bridge_revoke(
        remote_ca_cert: &Cert,
        ca_cert: &Cert,
    ) -> Fallible<(Signature, Cert)> {
        // there should be exactly one userid!
        assert_eq!(
            remote_ca_cert.userids().len(),
            1,
            "expect CA cert to have exactly one user_id"
        );
        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        // set_trust_signature, set_regular_expression(s), expiration

        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        // the CA should have exactly one key that can certify
        assert_eq!(cert_keys.len(), 1);

        let signer = &mut cert_keys[0];

        let mut packets: Vec<Packet> = Vec::new();

        let revocation_sig = cert::UserIDRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::Unspecified,
                b"removing OpenPGP CA bridge",
            )
            .unwrap()
            .build(signer, &remote_ca_cert, &userid, None)?;

        packets.push(revocation_sig.clone().into());

        let revoked = remote_ca_cert.clone().merge_packets(packets)?;

        Ok((revocation_sig, revoked))
    }

    /// CA signs all userids of Cert
    pub fn sign_user(ca_cert: &Cert, user: Cert) -> Fallible<Cert> {
        // sign Cert with CA key

        let mut cert_keys = Self::get_cert_keys(&ca_cert)
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        // FIXME: do we want to sign all uids?
        // (right now, this fn is only called for keys that the CA makes, so
        // that probably makes sense?)

        for uidb in user.userids() {
            for signer in &mut cert_keys {
                let uid = uidb.userid();

                let sig = uid.certify(signer, &user, None, None, None)?;

                sigs.push(sig.into());
            }
        }

        let certified = user.merge_packets(sigs)?;

        Ok(certified)
    }

    pub fn sign_user_emails(
        ca_cert: &Cert,
        user_cert: &Cert,
        emails: &[&str],
    ) -> Fallible<Cert> {
        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        let mut packets: Vec<Packet> = Vec::new();

        for uid in user_cert.userids() {
            for signer in &mut cert_keys {
                let userid = uid.userid();

                let uid_addr = userid
                    .email_normalized()?
                    .expect("email normalization failed");

                // Sign this userid if email has been given for this import call
                if emails.contains(&uid_addr.as_str()) {
                    // certify this userid
                    let sig = userid
                        .certify(signer, &user_cert, None, None, None)?;

                    packets.push(sig.into());
                }

                // FIXME: complain about emails that have been specified but
                // haven't been found in the userids?
                //            panic!("Email {} not found in the key", );
            }
        }

        let result = user_cert.clone().merge_packets(packets)?;
        Ok(result)
    }

    /// get all valid, certification capable keys with secret key material
    fn get_cert_keys(cert: &Cert) -> Fallible<Vec<KeyPair>> {
        let keys: ValidKeyIter<SecretParts> = cert
            .keys()
            .policy(None)
            .alive()
            .revoked(false)
            .for_certification()
            .secret();

        Ok(keys
            .filter_map(|ka| ka.key().clone().into_keypair().ok())
            .collect())
    }
}
