// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use crate::ca::{Backend, Card, DbCa};
use crate::db::{models, OcaDb};
use crate::pgp::Pgp;

use sequoia_openpgp::cert;
use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::{signature, Signature, UserID};
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
use sequoia_openpgp::{Cert, Packet};

use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};

use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Backend-specific implementation of certification operations
pub trait CertificationBackend {
    /// `op` should only use the Signer once.
    ///
    /// Some backends (e.g. OpenPGP card) may not allow more than one signing operation in one go.
    /// (cards can be configured to require presentation of PIN before each signing operation)
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()>;
}

impl CertificationBackend for DbCa {
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let ca_cert = self.ca_get_priv_key()?;
        let ca_keys = Pgp::get_cert_keys(&ca_cert, None);

        for mut s in ca_keys {
            op(&mut s as &mut dyn sequoia_openpgp::crypto::Signer)?;
        }

        Ok(())
    }
}

impl CertificationBackend for CardCa {
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let mut card = self.card.lock().unwrap();

        let mut pgp = OpenPgp::new(&mut *card);
        let mut open = Open::new(pgp.transaction()?)?;

        // FIXME: verifying PIN before each signing operation. Check if this is needed?
        open.verify_user_for_signing(self.pin.as_bytes())?;

        let mut sign = open
            .signing_card()
            .ok_or_else(|| anyhow!("Unexpected: can't get card in signing mode"))?;
        let mut signer = sign.signer(&|| println!("Touch confirmation needed for signing"))?;

        op(&mut signer as &mut dyn sequoia_openpgp::crypto::Signer)?;

        Ok(())
    }
}

/// Abstraction of operations that need private key material
pub trait CaSec: CertificationBackend {
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
    fn ca_generate_revocations(&self, output: PathBuf) -> Result<()> {
        let ca_pub = self.get_ca_cert()?;

        let mut file = std::fs::File::create(output)?;

        // write informational header
        writeln!(
            &mut file,
            "This file contains revocation certificates for the OpenPGP CA \n\
            instance '{}'.",
            self.ca_email()?
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
            Pgp::cert_to_armored(&ca_pub)?
        )?;

        writeln!(
            &mut file,
            "Revocation certificates (ordered by 'creation time') follow:\n"
        )?;

        let now = SystemTime::now();
        let thirty_days = Duration::new(30 * 24 * 60 * 60, 0);

        for i in 0..=120 {
            let t = now + i * thirty_days;

            let dt: DateTime<Utc> = t.into();
            let date = dt.format("%Y-%m-%d");

            self.certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                let hard = CertRevocationBuilder::new()
                    .set_signature_creation_time(t)?
                    .set_reason_for_revocation(
                        ReasonForRevocation::KeyCompromised,
                        b"Certificate has been compromised",
                    )?
                    .build(signer, &ca_pub, None)?;

                let header = vec![(
                    "Comment".to_string(),
                    format!("Hard revocation (certificate compromised) ({})", date),
                )];
                writeln!(
                    &mut file,
                    "{}\n",
                    &Pgp::revoc_to_armored(&hard, Some(header))?
                )?;

                Ok(())
            })?;

            self.certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                let soft = CertRevocationBuilder::new()
                    .set_signature_creation_time(t)?
                    .set_reason_for_revocation(
                        ReasonForRevocation::KeyRetired,
                        b"Certificate retired",
                    )?
                    .build(signer, &ca_pub, None)?;

                let header = vec![(
                    "Comment".to_string(),
                    format!("Soft revocation (certificate retired) ({})", date),
                )];
                writeln!(
                    &mut file,
                    "{}\n",
                    &Pgp::revoc_to_armored(&soft, Some(header))?
                )?;

                Ok(())
            })?;
        }

        Ok(())
    }

    /// Generate a detached signature with the CA key, for 'data'
    fn sign_detached(&self, data: &[u8]) -> Result<String>;

    /// CA certifies a specified list of User IDs of a cert.
    ///
    /// This fn does not perform any checks as a precondition for adding new
    /// certifications.
    fn sign_user_ids(
        &self,
        cert: &Cert,
        uids_certify: &[&UserID],
        duration_days: Option<u64>,
    ) -> Result<Cert> {
        let ca_cert = self.get_ca_cert()?; // pubkey (must include CA User ID!)

        // Collect certifications by the CA
        let mut packets: Vec<Packet> = Vec::new();

        let userids = cert
            .userids()
            // sign only userids that are in "uids_certify"
            .filter(|u| uids_certify.contains(&u.userid()))
            .map(|u| u.userid());

        for userid in userids {
            // make certification
            let mut sb = signature::SignatureBuilder::new(SignatureType::GenericCertification);

            // If an expiration setting for the certifications has been
            // provided, apply it to the signatures
            if let Some(days) = duration_days {
                // The signature should be valid for the specified
                // number of `days`
                sb = sb.set_signature_validity_period(Duration::from_secs(
                    Pgp::SECONDS_IN_DAY * days,
                ))?;
            }

            // Include 'Signer's UserID' packet
            // (https://tools.ietf.org/html/rfc4880#section-5.2.3.22)
            // to make it easier to find the CA key via WKD
            if let Some(uid) = ca_cert.userids().next() {
                sb = sb.set_signers_user_id(uid.userid().value())?;
            } else {
                return Err(anyhow::anyhow!(
                    "ERROR: No User ID in CA cert. This should never happen."
                ));
            }

            self.certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                let sig = userid.bind(signer, cert, sb.clone())?;

                // collect in packets
                packets.push(sig.into());

                Ok(())
            })?;
        }

        // Insert all newly created certifications into the user cert
        cert.clone().insert_packets(packets)
    }

    /// Add trust signature to the cert of a remote CA.
    ///
    /// If `scope_regexes` is empty, no regex scoping is added to the trust
    /// signature.
    fn bridge_to_remote_ca(&self, remote_ca: Cert, scope_regexes: Vec<String>) -> Result<Cert> {
        // There should be exactly one User ID in the remote CA Cert
        let uids: Vec<_> = remote_ca.userids().collect();

        if uids.len() == 1 {
            let userid = uids[0].userid();

            let mut packets: Vec<Packet> = Vec::new();

            let mut builder = signature::SignatureBuilder::new(SignatureType::GenericCertification)
                .set_trust_signature(255, 120)?;

            // add all regexes
            for regex in &scope_regexes {
                builder = builder.add_regular_expression(regex.as_bytes())?;
            }

            self.certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                // Create one tsig for each signer
                let tsig = userid.bind(signer, &remote_ca, builder.clone())?;
                packets.push(tsig.into());

                Ok(())
            })?;

            // FIXME: expiration?

            let signed = remote_ca.insert_packets(packets)?;

            Ok(signed)
        } else {
            Err(anyhow::anyhow!(
                "Remote CA cert doesn't have exactly one User ID"
            ))
        }
    }

    // FIXME: justus thinks this might not be supported by implementations
    fn bridge_revoke(&self, remote_ca: &Cert) -> Result<(Signature, Cert)> {
        // there should be exactly one userid in the remote CA Cert
        let uids: Vec<_> = remote_ca.userids().collect();

        let mut revocation_sig = None;
        let mut revoked = None;

        if uids.len() == 1 {
            let remote_uid = uids[0].userid();

            self.certify(&mut |signer: &mut dyn sequoia_openpgp::crypto::Signer| {
                // set_trust_signature, set_regular_expression(s), expiration
                let rev = cert::UserIDRevocationBuilder::new()
                    .set_reason_for_revocation(
                        ReasonForRevocation::Unspecified,
                        b"removing OpenPGP CA bridge",
                    )?
                    .build(signer, remote_ca, remote_uid, None)?;

                revocation_sig = Some(rev.clone());
                revoked = Some(remote_ca.clone().insert_packets(Packet::from(rev))?);

                Ok(())
            })?;

            if let (Some(sig), Some(cert)) = (revocation_sig, revoked) {
                Ok((sig, cert))
            } else {
                Err(anyhow::anyhow!("Failed to generate revocation signature"))
            }
        } else {
            Err(anyhow::anyhow!(
                "expect remote CA cert to have exactly one user_id"
            ))
        }
    }

    /// Get Cert for this CA (may contain private key material, depending on the backend)
    fn get_ca_cert(&self) -> Result<Cert>;

    fn ca_email(&self) -> Result<String>;
}

impl DbCa {
    /// Initialize OpenPGP CA Admin database entry.
    /// Takes a `cert` with private key material and initializes a softkey-based CA.
    ///
    /// Only one CA Admin can be configured per database.
    pub(crate) fn ca_init_softkey(&self, domainname: &str, cert: &Cert) -> Result<()> {
        if self.db().is_ca_initialized()? {
            return Err(anyhow::anyhow!("CA has already been initialized",));
        }

        let ca_key = Pgp::cert_to_armored_private_key(cert)?;

        self.db().ca_insert(
            models::NewCa {
                domainname,
                backend: None,
            },
            &ca_key,
            &cert.fingerprint().to_hex(),
        )
    }

    /// Get a sequoia `Cert` object for the CA from the database.
    ///
    /// This returns a full version of the CA Cert, including private key
    /// material.
    ///
    /// This is the OpenPGP Cert of the CA.
    ///
    /// CAUTION: getting the private key is not possible for OpenPGP cards,
    /// this fn should only be used for tests.
    fn ca_get_priv_key(&self) -> Result<Cert> {
        let (_, cert) = self.db().get_ca()?;

        Pgp::to_cert(cert.priv_cert.as_bytes())
    }
}

/// Implementation of CaSec based on a DbCa backend that contains the
/// private key material for the CA.
impl CaSec for DbCa {
    fn sign_detached(&self, data: &[u8]) -> Result<String> {
        let ca_cert = self.ca_get_priv_key()?;

        let signing_keypair = ca_cert
            .keys()
            .secret()
            .with_policy(Pgp::SP, None)
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
            let message = Armorer::new(message).build()?;

            let mut signer = Signer::new(message, signing_keypair).detached().build()?;

            // Write the data directly to the `Signer`.
            signer.write_all(data)?;
            signer.finalize()?;
        }

        Ok(std::str::from_utf8(&sink)?.to_string())
    }

    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db().get_ca()?;

        Pgp::to_cert(cacert.priv_cert.as_bytes())
    }

    fn ca_email(&self) -> Result<String> {
        self.ca_email()
    }
}

/// an OpenPGP card backend for a CA instance
pub(crate) struct CardCa {
    pin: String,

    db: Rc<OcaDb>,
    card: Arc<Mutex<PcscBackend>>,
}

impl CardCa {
    pub(crate) fn new(ident: &str, pin: &str, db: Rc<OcaDb>) -> Result<Self> {
        let card = PcscBackend::open_by_ident(ident, None)?;

        let card = Arc::new(Mutex::new(card));

        Ok(Self {
            pin: pin.to_string(),
            db,
            card,
        })
    }

    pub(crate) fn ca_init(
        db: &Rc<OcaDb>,
        domainname: &str,
        card_ident: &str,
        pin: &str,
        pubkey: &str,
        fingerprint: &str,
    ) -> Result<()> {
        // FIXME: missing logic from DbCa::ca_init()? (e.g. domain name syntax check)

        let backend = Backend::Card(Card {
            ident: card_ident.to_string(),
            user_pin: pin.to_string(),
        });

        db.ca_insert(
            models::NewCa {
                domainname,
                backend: backend.to_config().as_deref(),
            },
            pubkey,
            fingerprint,
        )
    }

    // FIXME: code duplication, remove!
    fn ca_userid(&self) -> Result<UserID> {
        let cert = self.get_ca_cert()?;
        let uids: Vec<_> = cert.userids().collect();

        if uids.len() != 1 {
            return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
        }

        Ok(uids[0].userid().clone())
    }
}

impl CaSec for CardCa {
    // FIXME: this function is implemented here, because apparently it can't be implemented based
    // on the CertificationBackend trait:
    // Making a detached signature seems to require an owned crypto::Signer of a concrete type.
    fn sign_detached(&self, data: &[u8]) -> Result<String> {
        let mut card = self.card.lock().unwrap();

        let mut pgp = OpenPgp::new(&mut *card);
        let mut open = Open::new(pgp.transaction()?)?;

        // FIXME: verifying PIN before each signing operation. Check if this is needed?
        open.verify_user_for_signing(self.pin.as_bytes())?;

        let mut sign = open
            .signing_card()
            .ok_or_else(|| anyhow!("Unexpected: can't get card in signing mode"))?;
        let signer = sign.signer(&|| println!("Touch confirmation needed for signing"))?;

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message).build()?;

            let mut signer = Signer::new(message, signer).detached().build()?;

            // Write the data directly to the `Signer`.
            signer.write_all(data)?;
            signer.finalize()?;
        }

        Ok(std::str::from_utf8(&sink)?.to_string())
    }

    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db.get_ca()?;

        Pgp::to_cert(cacert.priv_cert.as_bytes())
    }

    // FIXME: code duplication, remove!
    fn ca_email(&self) -> Result<String> {
        let email = self.ca_userid()?.email()?;

        if let Some(email) = email {
            Ok(email)
        } else {
            Err(anyhow::anyhow!("CA user_id has no email"))
        }
    }
}
