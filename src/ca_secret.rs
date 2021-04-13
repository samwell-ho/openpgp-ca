// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::{DbCa, OpenpgpCa};
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::{signature, UserID};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
use sequoia_openpgp::{Cert, Packet};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use sequoia_openpgp::packet::signature::SignatureBuilder;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const POLICY: &StandardPolicy = &StandardPolicy::new();

/// abstraction of operations that need private key material
pub trait CaSec {
    fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()>;

    fn ca_generate_revocations(
        &self,
        oca: &OpenpgpCa,
        output: PathBuf,
    ) -> Result<()>;

    fn ca_import_tsig(&self, cert: &str) -> Result<()>;

    fn bridge_to_remote_ca(
        &self,
        remote_ca_cert: Cert,
        scope_regexes: Vec<String>,
    ) -> Result<Cert>;

    fn sign_detached(&self, text: &str) -> Result<String>;

    fn sign_user_emails(
        &self,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
        duration_days: Option<u64>,
    ) -> Result<Cert>;

    fn sign_user_ids(
        &self,
        user_cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert>;

    /// CAUTION: getting the private key is not possible for OpenPGP cards,
    /// this fn should only be used for tests.
    fn ca_get_priv_key(&self) -> Result<Cert>;
}

/// Operations that require CA private key material
impl CaSec for DbCa {
    fn ca_init(&self, domainname: &str, name: Option<&str>) -> Result<()> {
        if self.db().get_ca()?.is_some() {
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

        self.db().transaction(|| {
            self.db().insert_ca(
                models::NewCa { domainname },
                ca_key,
                &cert.fingerprint().to_hex(),
            )
        })
    }

    fn ca_generate_revocations(
        &self,
        oca: &OpenpgpCa,
        output: PathBuf,
    ) -> Result<()> {
        let ca = self.ca_get_priv_key()?;

        let mut file = std::fs::File::create(output)?;

        // write informational header
        writeln!(
            &mut file,
            "This file contains revocation certificates for the OpenPGP CA \n\
            instance '{}'.",
            oca.get_ca_email()?
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

    fn ca_import_tsig(&self, cert: &str) -> Result<()> {
        self.db().transaction(|| {
            let ca_cert = self.ca_get_priv_key()?;

            let cert_import = Pgp::armored_to_cert(cert)?;

            // make sure the keys have the same Fingerprint
            if ca_cert.fingerprint() != cert_import.fingerprint() {
                return Err(anyhow::anyhow!(
                    "The imported cert has an unexpected Fingerprint",
                ));
            }

            // get the tsig(s) from import
            let tsigs = Pgp::get_trust_sigs(&cert_import)?;

            // add tsig(s) to our "own" version of the CA key
            let mut packets: Vec<Packet> = Vec::new();
            tsigs.iter().for_each(|s| packets.push(s.clone().into()));

            let signed = ca_cert
                .insert_packets(packets)
                .context("merging tsigs into CA Key failed")?;

            // update in DB
            let (_, mut ca_cert) = self
                .db()
                .get_ca()
                .context("failed to load CA from database")?
                .unwrap();

            ca_cert.priv_cert = Pgp::cert_to_armored_private_key(&signed)
                .context("failed to armor CA Cert")?;

            self.db()
                .update_cacert(&ca_cert)
                .context("Update of CA Cert in DB failed")
        })
    }

    /// add trust signature to the public key of a remote CA
    fn bridge_to_remote_ca(
        &self,
        remote_ca_cert: Cert,
        scope_regexes: Vec<String>,
    ) -> Result<Cert> {
        let ca_cert = self.ca_get_priv_key()?;

        // FIXME: do we want to support a tsig without any scope regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid in the remote CA Cert
        if remote_ca_cert.userids().len() != 1 {
            return Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id",
            ));
        }

        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        let mut cert_keys = Pgp::get_cert_keys(&ca_cert, None);

        let mut packets: Vec<Packet> = Vec::new();

        // create one tsig for each signer
        for signer in &mut cert_keys {
            let mut builder =
                SignatureBuilder::new(SignatureType::GenericCertification)
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

    fn sign_detached(&self, text: &str) -> Result<String> {
        let ca_cert = self.ca_get_priv_key()?;

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

    /// ca_cert certifies either all or a specified subset of userids of
    /// user_cert
    fn sign_user_emails(
        &self,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        let fp_ca = self.ca_get_priv_key()?.fingerprint();

        let mut uids = Vec::new();

        for uid in user_cert.userids() {
            // check if this uid already has a valid signature by ca_cert.
            // if yes, don't add another one.
            if !uid
                .clone()
                .with_policy(POLICY, None)?
                .certifications()
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

        self.sign_user_ids(user_cert, &uids, duration_days)
    }

    /// ca_cert certifies a specified list of userids of user_cert.
    ///
    /// This fn does not perform any checks as a precondition for adding new
    /// certifications.
    fn sign_user_ids(
        &self,
        user_cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        let ca_cert = self.ca_get_priv_key()?;

        let mut cert_keys = Pgp::get_cert_keys(&ca_cert, None);

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

                // Include 'Signer's UserID' packet
                // (https://tools.ietf.org/html/rfc4880#section-5.2.3.22)
                // to make it easier to find the CA key via WKD
                if let Some(uid) = ca_cert.userids().next() {
                    sb = sb.set_signers_user_id(uid.userid().value())?;
                } else {
                    panic!("no user id in ca cert. this should never happen.");
                }

                let sig = userid.bind(signer, user_cert, sb)?;

                // collect all certifications
                packets.push(sig.into());
            }
        }

        // insert all new certifications into user_cert
        user_cert.clone().insert_packets(packets)
    }

    fn ca_get_priv_key(&self) -> Result<Cert> {
        match self.db().get_ca()? {
            Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.priv_cert)?),
            _ => panic!("get_ca_cert() failed"),
        }
    }
}
