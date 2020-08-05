// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
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
use openpgp::cert::amalgamation::{ValidAmalgamation, ValidateAmalgamation};
use openpgp::crypto::KeyPair;
use openpgp::packet::{signature, Signature, UserID};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::SerializeInto;
use openpgp::types::{
    KeyFlags, ReasonForRevocation, RevocationStatus, SignatureType,
};
use openpgp::{Cert, Fingerprint, KeyHandle, Packet};

use std::convert::identity;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use sequoia_openpgp::cert::amalgamation::key::ValidKeyAmalgamation;
use sha2::Digest;

pub struct Pgp {}

impl Pgp {
    fn diceware() -> String {
        // FIXME: configurable dictionaries, ... ?
        use chbs::passphrase;
        passphrase()
    }

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
    ) -> Result<(Cert, Signature)> {
        // FIXME: should not be encryption capable (?)
        // FIXME: should not have subkeys

        // Generate a Cert, and create a keypair from the primary key.
        let (cert, sig) = cert::CertBuilder::new()
            .add_signing_subkey()
            // FIXME: set expiration from CLI
            // std::time::Duration::new(123456, 0)
            .set_expiration_time(None)
            .generate()?;

        let mut keypair = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        // Generate a userid and a binding signature.
        let email = format!("openpgp-ca@{}", domainname);
        let userid = Self::user_id(&email, name);

        let policy = StandardPolicy::new();

        let direct_key_sig = cert
            .primary_key()
            .with_policy(&policy, None)?
            .binding_signature();
        let builder =
            signature::SignatureBuilder::from(direct_key_sig.clone())
                .set_type(SignatureType::PositiveCertification)
                .set_key_flags(&KeyFlags::empty().set_certification())?
                // notation: "openpgp-ca:domain=domain1;domain2"
                .add_notation(
                    "openpgp-ca@sequoia-pgp.org",
                    (format!("domain={}", domainname)).as_bytes(),
                    signature::subpacket::NotationDataFlags::default()
                        .set_human_readable(true),
                    false,
                )?;
        let binding = userid.bind(&mut keypair, &cert, builder)?;

        // Now merge the userid and binding signature into the Cert.
        let cert =
            cert.merge_packets(vec![Packet::from(userid), binding.into()])?;

        Ok((cert, sig))
    }

    /// Makes a user Cert with "emails" as UIDs.
    pub fn make_user_cert(
        emails: &[&str],
        name: Option<&str>,
        password: bool,
    ) -> Result<(Cert, Signature, Option<String>)> {
        // FIXME: use passphrase

        let pass = if password {
            Some(Self::diceware())
        } else {
            None
        };

        let mut builder = cert::CertBuilder::new()
            .add_subkey(
                KeyFlags::default()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            )
            .add_signing_subkey();

        if let Some(pass) = &pass {
            builder = builder.set_password(Some(pass.to_owned().into()));
        }

        for email in emails {
            builder = builder.add_userid(Self::user_id(&email, name));
        }

        let (cert, sig) = builder.generate()?;
        Ok((cert, sig, pass))
    }

    /// make a "public key" ascii-armored representation of a Cert
    pub fn cert_to_armored(cert: &Cert) -> Result<String> {
        let v = cert.armored().to_vec().context("Cert serialize failed")?;

        Ok(String::from_utf8(v)?)
    }

    /// make a "private key" ascii-armored representation of a Cert
    pub fn priv_cert_to_armored(cert: &Cert) -> Result<String> {
        let mut buffer = vec![];
        {
            let headers = cert.armor_headers();
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let mut writer = armor::Writer::with_headers(
                &mut buffer,
                armor::Kind::SecretKey,
                headers,
            )
            .unwrap();

            cert.as_tsk().serialize(&mut writer)?;
            writer.finalize()?;
        }

        Ok(String::from_utf8(buffer)?)
    }

    /// make a Cert from an ascii armored key
    pub fn armored_to_cert(armored: &str) -> Result<Cert> {
        let cert =
            Cert::from_bytes(armored).context("Cert::from_bytes failed")?;

        Ok(cert)
    }

    /// make a Signature from an ascii armored signature
    pub fn armored_to_signature(armored: &str) -> Result<Signature> {
        let p = openpgp::Packet::from_bytes(armored)
            .context("Input could not be parsed")?;

        if let Packet::Signature(s) = p {
            Ok(s)
        } else {
            Err(anyhow::anyhow!("Couldn't convert to Signature"))
        }
    }

    /// make an ascii-armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Result<String> {
        let mut buf = vec![];
        {
            let rev = Packet::Signature(sig.clone());

            let mut writer =
                armor::Writer::new(&mut buf, armor::Kind::Signature).unwrap();
            rev.serialize(&mut writer)?;
            writer.finalize()?;
        }

        Ok(String::from_utf8(buf)?)
    }

    /// get expiration of cert as SystemTime
    pub fn get_expiry(cert: &Cert) -> Result<Option<SystemTime>> {
        let policy = StandardPolicy::new();
        let primary = cert.primary_key().with_policy(&policy, None)?;
        Ok(primary.key_expiration_time())
    }

    /// is (possibly) revoked
    pub fn is_possibly_revoked(cert: &Cert) -> bool {
        RevocationStatus::NotAsFarAsWeKnow
            != cert.revocation_status(&StandardPolicy::new(), None)
    }

    /// Load Revocation Cert from file
    pub fn load_revocation_cert(
        revoc_file: Option<&PathBuf>,
    ) -> Result<Signature> {
        if let Some(filename) = revoc_file {
            let p = openpgp::Packet::from_file(filename)
                .context("Input could not be parsed")?;

            if let Packet::Signature(s) = p {
                return Ok(s);
            } else {
                return Err(anyhow::anyhow!("Couldn't convert to revocation"));
            }
        };
        Err(anyhow::anyhow!("Couldn't load revocation from file"))
    }

    pub fn get_revoc_issuer_fp(revoc_cert: &Signature) -> Option<Fingerprint> {
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
            .filter_map(identity)
            .collect();

        match sig_fingerprints.len() {
            0 => None,
            1 => Some(sig_fingerprints[0].clone()),
            _ => panic!("expected 0 or 1 issuer fingerprint in revocation"),
        }
    }

    /// Generate a 64 bit sized hash of a revocation certificate
    /// (represented as 16 character hex strings).
    ///
    /// These hashes can be used to refer to specific revocations.
    pub fn revocation_to_hash(revoc: &str) -> Result<String> {
        let sig = Pgp::armored_to_signature(revoc)?;

        let p: Packet = sig.into();
        let bits = p.to_vec()?;

        use sha2::Sha256;

        let mut hasher = Sha256::new();
        hasher.update(bits);
        let hash64 = &hasher.finalize()[0..8];

        let hex = hash64
            .iter()
            .map(|d| format!("{:02X}", d))
            .collect::<Vec<_>>()
            .concat();

        Ok(hex)
    }

    /// user tsigns CA key
    pub fn tsign_ca(
        ca_cert: Cert,
        user: &Cert,
        pass: Option<&str>,
    ) -> Result<Cert> {
        let mut cert_keys = Self::get_cert_keys(&user, pass)
            .context("filtered for unencrypted secret keys above")?;

        assert!(!cert_keys.is_empty(), "Can't find usable user key");

        let mut sigs: Vec<Signature> = Vec::new();

        // create a TSIG for each UserID
        for ca_uidb in ca_cert.userids() {
            for signer in &mut cert_keys {
                let builder = signature::SignatureBuilder::new(
                    SignatureType::GenericCertification,
                )
                .set_trust_signature(255, 120)?;

                let tsig = ca_uidb.userid().bind(signer, &ca_cert, builder)?;
                sigs.push(tsig);
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
    ) -> Result<Cert> {
        // FIXME: do we want to support a tsig without any scope regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid in the remote CA Cert
        if remote_ca_cert.userids().len() != 1 {
            return Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id",
            ));
        }

        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        let mut cert_keys = Self::get_cert_keys(&ca_cert, None)?;

        let mut packets: Vec<Packet> = Vec::new();

        // create one TSIG for each regex
        for regex in scope_regexes {
            for signer in &mut cert_keys {
                let builder = signature::SignatureBuilder::new(
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
    ) -> Result<(Signature, Cert)> {
        // there should be exactly one userid in the remote CA Cert
        if remote_ca_cert.userids().len() != 1 {
            return Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id",
            ));
        }

        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        // set_trust_signature, set_regular_expression(s), expiration

        let mut cert_keys = Self::get_cert_keys(&ca_cert, None)?;

        // this CA should have exactly one key that can certify
        if cert_keys.len() != 1 {
            return Err(anyhow::anyhow!(
                "this CA should have exactly one key that can certify",
            ));
        }

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

    /// CA signs all, or a specified list of userids of Cert
    pub fn sign_user_emails(
        ca_cert: &Cert,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
    ) -> Result<Cert> {
        let policy = StandardPolicy::new();

        let mut cert_keys = Self::get_cert_keys(&ca_cert, None)
            .context("filtered for unencrypted secret keys above")?;

        let fp_ca = ca_cert.fingerprint();

        let mut packets: Vec<Packet> = Vec::new();

        'uid: for uid in user_cert.userids() {
            // check if this uid already has a signature by ca_cert.
            // if yes, don't add another one.
            let sigs = uid
                .clone()
                .with_policy(&policy, None)?
                .bundle()
                .certifications();
            if sigs.iter().any(|s| s.issuer_fingerprint() == Some(&fp_ca)) {
                // there is already a signature by ca_cert on this uid - skip
                continue;
            }

            for signer in &mut cert_keys {
                let userid = uid.userid();

                let uid_addr = userid
                    .email_normalized()?
                    .expect("email normalization failed");

                // did we get a filter-list for email addresses?
                if let Some(emails) = emails_filter {
                    // if so, don't process this userid if the email is
                    // not in the list
                    if !emails.contains(&uid_addr.as_str()) {
                        // don't certify this userid
                        continue 'uid;
                    }
                }

                let sig =
                    userid.certify(signer, &user_cert, None, None, None)?;

                packets.push(sig.into());

                // FIXME: complain about emails that have been specified but
                // haven't been found in the userids?
                //            panic!("Email {} not found in the key", );
            }
        }

        Ok(user_cert.clone().merge_packets(packets)?)
    }

    /// get all valid, certification capable keys with secret key material
    fn get_cert_keys(
        cert: &Cert,
        password: Option<&str>,
    ) -> Result<Vec<KeyPair>> {
        let policy = StandardPolicy::new();
        let keys = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_certification()
            .secret();

        Ok(keys
            .filter_map(|ka: ValidKeyAmalgamation<_, _, _>| {
                let mut ka = ka.key().clone();

                if let Some(password) = password {
                    ka = ka.decrypt_secret(&password.into()).ok()?
                }

                ka.into_keypair().ok()
            })
            .collect())
    }
}
