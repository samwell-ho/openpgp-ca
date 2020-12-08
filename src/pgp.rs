// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

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
use sequoia_openpgp::cert::CipherSuite;
use sha2::Digest;

const POLICY: &StandardPolicy = &StandardPolicy::new();

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
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_signing_subkey()
            // FIXME: set expiration from CLI
            // .set_validity_period()
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

        let direct_key_sig = cert
            .primary_key()
            .with_policy(POLICY, None)?
            .binding_signature();
        let builder =
            signature::SignatureBuilder::from(direct_key_sig.clone())
                .set_type(SignatureType::PositiveCertification)
                .set_key_flags(KeyFlags::empty().set_certification())?
                // notation: "openpgp-ca:domain=domain1;domain2"
                .add_notation(
                    "openpgp-ca@sequoia-pgp.org",
                    (format!("domain={}", domainname)).as_bytes(),
                    signature::subpacket::NotationDataFlags::empty()
                        .set_human_readable(),
                    false,
                )?;
        let binding = userid.bind(&mut keypair, &cert, builder)?;

        // Now merge the userid and binding signature into the Cert.
        let cert =
            cert.insert_packets(vec![Packet::from(userid), binding.into()])?;

        Ok((cert, sig))
    }

    /// Makes a user Cert with "emails" as UIDs.
    pub fn make_user_cert(
        emails: &[&str],
        name: Option<&str>,
        password: bool,
    ) -> Result<(Cert, Signature, Option<String>)> {
        let pass = if password {
            Some(Self::diceware())
        } else {
            None
        };

        let mut builder = cert::CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA4k)
            .add_subkey(
                KeyFlags::empty()
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

    /// Get the armored "keyring" representation of a List of public-key Certs
    pub fn certs_to_armored(certs: &[Cert]) -> Result<String> {
        let mut writer =
            armor::Writer::new(Vec::new(), armor::Kind::PublicKey)?;

        for cert in certs {
            cert.serialize(&mut writer)?;
        }
        let buffer = writer.finalize()?;

        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    /// make a "private key" ascii-armored representation of a Cert
    pub fn cert_to_armored_private_key(cert: &Cert) -> Result<String> {
        let mut buffer = vec![];

        let headers: Vec<_> = cert
            .armor_headers()
            .into_iter()
            .map(|value| ("Comment", value))
            .collect();

        let mut writer = armor::Writer::with_headers(
            &mut buffer,
            armor::Kind::SecretKey,
            headers,
        )?;

        cert.as_tsk().serialize(&mut writer)?;
        writer.finalize()?;

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
                armor::Writer::new(&mut buf, armor::Kind::Signature)?;
            rev.serialize(&mut writer)?;
            writer.finalize()?;
        }

        Ok(String::from_utf8(buf)?)
    }

    /// get expiration of cert as SystemTime
    pub fn get_expiry(cert: &Cert) -> Result<Option<SystemTime>> {
        let primary = cert.primary_key().with_policy(POLICY, None)?;
        Ok(primary.key_expiration_time())
    }

    /// is (possibly) revoked
    pub fn is_possibly_revoked(cert: &Cert) -> bool {
        RevocationStatus::NotAsFarAsWeKnow
            != cert.revocation_status(POLICY, None)
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

        let signed = ca_cert.insert_packets(sigs)?;

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

        // create one tsig for each signer
        for signer in &mut cert_keys {
            let mut builder = signature::SignatureBuilder::new(
                SignatureType::GenericCertification,
            )
            .set_trust_signature(255, 120)?;

            // add all regexes
            for regex in &scope_regexes {
                builder = builder.add_regular_expression(regex.as_bytes())?;
            }

            let tsig = userid.bind(signer, &remote_ca_cert, builder)?;

            packets.push(tsig.into());
        }

        // FIXME: expiration?

        let signed = remote_ca_cert.insert_packets(packets)?;

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
            )?
            .build(signer, &remote_ca_cert, &userid, None)?;

        packets.push(revocation_sig.clone().into());

        let revoked = remote_ca_cert.clone().insert_packets(packets)?;

        Ok((revocation_sig, revoked))
    }

    /// ca_cert certifies a specified list of userids of user_cert.
    ///
    /// This fn does not perform any checks as a precondition for adding new
    /// certifications.
    pub fn sign_user_ids(
        ca_cert: &Cert,
        user_cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        let mut cert_keys = Self::get_cert_keys(&ca_cert, None)
            .context("filtered for unencrypted secret keys above")?;

        let mut packets: Vec<Packet> = Vec::new();

        for userid in user_cert
            .userids()
            // sign only userids that are in "uids_certify"
            .filter(|u| uids_certify.contains(&u.userid()))
            .map(|u| u.userid())
        {
            for signer in &mut cert_keys {
                // make certification
                let mut sb = signature::SignatureBuilder::new(
                    SignatureType::GenericCertification,
                );
                if let Some(days) = duration_days {
                    // the signature should be good for "days" days from now
                    const SECONDS_IN_DAY: u64 = 60 * 60 * 24;
                    sb = sb.set_signature_validity_period(
                        std::time::Duration::new(SECONDS_IN_DAY * days, 0),
                    )?;
                }
                let sig = userid.bind(signer, user_cert, sb)?;

                // collect all certifications
                packets.push(sig.into());
            }
        }

        // insert all new certifications into user_cert
        Ok(user_cert.clone().insert_packets(packets)?)
    }

    /// ca_cert certifies either all or a specified subset of userids of
    /// user_cert
    pub fn sign_user_emails(
        ca_cert: &Cert,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        let fp_ca = ca_cert.fingerprint();

        let mut uids = Vec::new();

        for uid in user_cert.userids() {
            // check if this uid already has a valid signature by ca_cert.
            // if yes, don't add another one.
            if !uid
                .clone()
                .with_policy(POLICY, None)?
                .certifications()
                .iter()
                .any(|s| s.issuer_fingerprints().any(|fp| fp == &fp_ca))
            {
                let userid = uid.userid();
                let uid_addr = userid
                    .email_normalized()?
                    .expect("email normalization failed");

                // certify this userid if we
                // a) have no filter-list, or
                // b) if the userid is specified in the filter-list
                if emails_filter.is_none()
                    || emails_filter.unwrap().contains(&uid_addr.as_str())
                {
                    uids.push(userid);
                }
            }
        }

        // FIXME: complain about emails that have been specified but
        // haven't been found in the userids?
        //            panic!("Email {} not found in the key", );

        Self::sign_user_ids(ca_cert, user_cert, &uids, duration_days)
    }

    /// get all valid, certification capable keys with secret key material
    fn get_cert_keys(
        cert: &Cert,
        password: Option<&str>,
    ) -> Result<Vec<KeyPair>> {
        let keys = cert
            .keys()
            .with_policy(POLICY, None)
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
