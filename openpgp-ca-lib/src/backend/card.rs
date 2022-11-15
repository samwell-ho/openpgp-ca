// SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::convert::TryFrom;
use std::ops::DerefMut;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use openpgp_card::{algorithm::AlgoSimple, KeyType};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::state::{Admin, Open, Transaction};
use openpgp_card_sequoia::util::public_key_material_to_key;
use openpgp_card_sequoia::{sq_util, Card, PublicKey};
use sequoia_openpgp::packet::key::{KeyRole, PrimaryRole, SubordinateRole};
use sequoia_openpgp::packet::prelude::SignatureBuilder;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{
    Features, HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};

use crate::backend;
use crate::backend::{Backend, CertificationBackend};
use crate::ca_secret::CaSec;
use crate::db::{models, OcaDb};
use crate::pgp::Pgp;

/// an OpenPGP card backend for a CA instance
pub(crate) struct CardCa {
    pin: String,

    db: Rc<OcaDb>,
    card: Arc<Mutex<Card<Open>>>,
}

impl CertificationBackend for CardCa {
    fn certify(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let mut card = self.card.lock().unwrap();

        let card = card.deref_mut();
        let mut open = card.transaction()?;

        // FIXME: verifying PIN before each signing operation. Check if this is needed?
        open.verify_user(self.pin.as_bytes())?;

        let mut user = open
            .user_card()
            .ok_or_else(|| anyhow!("Unexpected: can't get card in signing mode"))?;
        let mut signer =
            user.authenticator(&|| println!("Touch confirmation needed for signing"))?;

        op(&mut signer as &mut dyn sequoia_openpgp::crypto::Signer)?;

        Ok(())
    }

    fn sign(
        &self,
        op: &mut dyn FnMut(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<()>,
    ) -> Result<()> {
        let mut card = self.card.lock().unwrap();

        let card = card.deref_mut();
        let mut open = card.transaction()?;

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

impl CardCa {
    pub(crate) fn new(ident: &str, pin: &str, db: Rc<OcaDb>) -> Result<Self> {
        let backend = PcscBackend::open_by_ident(ident, None)?;
        let card: Card<Open> = backend.into();

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

        let backend = Backend::Card(backend::Card {
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
}

impl CaSec for CardCa {
    fn get_ca_cert(&self) -> Result<Cert> {
        let (_, cacert) = self.db.get_ca()?;

        Pgp::to_cert(cacert.priv_cert.as_bytes())
    }
}

// The default Admin PIN for a factory reset card.
// We assume that we start unconfigured cards for setting up card-based CAs,
// so we assume the default Admin PIN can be used.
const PW3_DEFAULT: &str = "12345678";

/// Check if the card `ident` is empty.
/// The card is considered empty when fingerprints for all three keyslots are unset.
pub(crate) fn check_card_empty(open: &Card<Transaction>) -> Result<bool> {
    let fps = open.fingerprints()?;
    if fps.signature().is_some() || fps.decryption().is_some() || fps.authentication().is_some() {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Generate a new certification key on the card, return its public key representation.
///
/// Expects Admin PIN to be set to the default value of `12345678`.
/// During card setup, this fn resets the User PIN to a new, random, 8 digit value.
pub(crate) fn generate_on_card(
    ident: &str,
    domain: &str,
    user_id: String,
) -> Result<(Cert, String)> {
    let backend = PcscBackend::open_by_ident(ident, None)?;
    let mut card: Card<Open> = backend.into();
    let mut transaction = card.transaction()?;

    // check that card has no keys on it
    if !check_card_empty(&transaction)? {
        return Err(anyhow!(
            "The OpenPGP card contains key material, please reset it before use with OpenPGP CA."
        ));
    }

    // Use RSA4k by default. This works on e.g. Yk5 (but Gnuk can't generate rsa4k)
    let algo = Some(AlgoSimple::RSA4k);

    // Print information about algorithm and possible slowness.
    println!(
        "Generating {}key material on the card, this might take a while.",
        // Printable algo name (with trailing space, if not 'None')
        if let Some(algo) = algo {
            format!("{:?} ", algo)
        } else {
            "".to_string()
        }
    );
    println!();

    // We assume that the default Admin PIN is currently valid
    if transaction.verify_admin(PW3_DEFAULT.as_bytes()).is_err() {
        return Err(anyhow!(
            "Failed to get Admin access to the card with the default PIN."
        ));
    };

    if let Ok(mut admin) = transaction
        .admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access"))
    {
        let (pkm, ts) = admin.generate_key_simple(KeyType::Signing, algo)?;
        admin.set_name("OpenPGP CA")?;

        let key_sig = public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None)?;

        let (pkm, ts) = admin.generate_key_simple(KeyType::Authentication, algo)?;

        let key_aut = public_key_material_to_key(&pkm, KeyType::Authentication, &ts, None, None)?;

        // Change User and Admin PIN
        //
        // NOTE: This is done after key generation because Gnuk doesn't allow PIN changes
        // when the card contains no keys.
        let new_pin = set_user_and_admin_pin(&mut admin, PW3_DEFAULT)?;

        // Custom Certificate generation: we use the auth slot as the certification capable primary
        // key, and the signing key from the sig slot.

        let cert = {
            let mut pp = vec![];

            fn set_signer_metadata(sb: SignatureBuilder) -> Result<SignatureBuilder> {
                sb.set_features(Features::sequoia())?
                    .set_preferred_hash_algorithms(vec![
                        HashAlgorithm::SHA512,
                        HashAlgorithm::SHA256,
                    ])?
                    .set_preferred_symmetric_algorithms(vec![
                        SymmetricAlgorithm::AES256,
                        SymmetricAlgorithm::AES128,
                    ])
            }

            // helper: use the card's auth slot to perform a certification operation
            fn certify_on_card(
                user_pin: &str,
                card: &mut Card<Transaction>,
                auth_pubkey: PublicKey,
                op: &mut dyn Fn(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<Signature>,
            ) -> Result<Signature> {
                // Allow user operations on the card
                let pw1 = user_pin.as_bytes();
                card.verify_user(pw1)?;

                // FIXME: implement pin pad handling
                // open.verify_user_pinpad(&|| {
                //     println!("Enter User PIN on card reader pinpad.")
                // })?;

                if let Some(mut user) = card.user_card() {
                    // Card-backed signer for bindings
                    let mut card_signer = user.authenticator_from_public(auth_pubkey, &|| {
                        println!("Need touch confirmation for signing.")
                    });

                    // Make signature, return it
                    let s = op(&mut card_signer)?;
                    Ok(s)
                } else {
                    Err(anyhow!("Failed to open card for signing"))
                }
            }

            // helper: use the card's sig slot to perform a signing operation
            fn sign_on_card(
                user_pin: &str,
                card: &mut Card<Transaction>,
                sig_pubkey: PublicKey,
                op: &mut dyn Fn(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<Signature>,
            ) -> Result<Signature> {
                // Allow user operations on the card
                let pw1 = user_pin.as_bytes();
                card.verify_user_for_signing(pw1)?;

                // FIXME: implement pin pad handling
                // open.verify_user_pinpad(&|| {
                //     println!("Enter User PIN on card reader pinpad.")
                // })?;

                if let Some(mut sign) = card.signing_card() {
                    // Card-backed signer for bindings
                    let mut card_signer = sign.signer_from_public(sig_pubkey, &|| {
                        println!("Need touch confirmation for signing.")
                    });

                    // Make signature, return it
                    let s = op(&mut card_signer)?;
                    Ok(s)
                } else {
                    Err(anyhow!("Failed to open card for signing"))
                }
            }

            // 1) use the auth key as primary key
            let pri = PrimaryRole::convert_key(key_aut.clone());
            pp.push(Packet::from(pri));

            // 2) make direct key signature
            let s = certify_on_card(&new_pin, &mut transaction, key_aut.clone(), &mut |signer| {
                let sb = SignatureBuilder::new(SignatureType::DirectKey).set_key_flags(
                    // Flags for primary key
                    KeyFlags::empty().set_certification(),
                )?;
                let sb = set_signer_metadata(sb)?;
                let sb = Pgp::add_ca_domain_notation(sb, domain)?;

                sb.sign_direct_key(signer, key_aut.role_as_primary())
            })?;
            pp.push(s.into());

            // 3) add `user_id`.
            let uid: UserID = user_id.into();
            pp.push(uid.clone().into());

            // Temporary version of the cert
            let cert = Cert::try_from(pp.clone())?;

            // 4) make, sign userid binding -> add
            let s = certify_on_card(&new_pin, &mut transaction, key_aut.clone(), &mut |signer| {
                let sb = SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_key_flags(
                        // Flags for primary key
                        KeyFlags::empty().set_certification(),
                    )?;
                let sb = set_signer_metadata(sb)?;
                let sb = Pgp::add_ca_domain_notation(sb, domain)?;

                uid.bind(signer, &cert, sb)
            })?;
            pp.push(s.into());

            // Temporary version of the cert
            let cert = Cert::try_from(pp.clone())?;

            // 5) backsig
            let sub_sig = SubordinateRole::convert_key(key_sig.clone());

            let bs = sign_on_card(&new_pin, &mut transaction, key_sig, &mut |signer| {
                let sb = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    // GnuPG wants at least a 512-bit hash for P521 keys.
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .set_reference_time(None);

                sb.sign_primary_key_binding(&mut *signer, &cert.primary_key(), &sub_sig)
            })?;

            // Temporary version of the cert
            let cert = Cert::try_from(pp.clone())?;

            // 6) add sig subkey
            pp.push(Packet::from(sub_sig.clone()));

            // 7) make, certify subkey binding -> add
            let s = certify_on_card(&new_pin, &mut transaction, key_aut.clone(), &mut |signer| {
                let sb = SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(KeyFlags::empty().set_signing())?
                    .set_embedded_signature(bs.clone())?;

                sub_sig.bind(signer, &cert, sb)
            })?;
            pp.push(s.into());

            Cert::try_from(pp)
        }?;

        Ok((cert, new_pin))
    } else {
        Err(anyhow!("Failed to open card in admin mode."))
    }
}

/// Returns newly set User PIN
pub(crate) fn import_to_card(ident: &str, key: &Cert) -> Result<String> {
    let backend = PcscBackend::open_by_ident(ident, None)?;
    let mut card: Card<Open> = backend.into();
    let mut transaction = card.transaction()?;

    // check that card has no keys on it
    if !check_card_empty(&transaction)? {
        return Err(anyhow!(
            "The OpenPGP card contains key material, please reset it before use with OpenPGP CA."
        ));
    }

    transaction.verify_admin(PW3_DEFAULT.as_bytes())?;

    if let Ok(mut admin) = transaction
        .admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access"))
    {
        let policy = StandardPolicy::new();

        let mut certifier: Vec<_> = key
            .keys()
            .with_policy(&policy, None)
            .secret()
            .for_certification()
            .collect();

        match certifier.len() {
            1 => {
                let cert = certifier.pop().unwrap();
                let dec = sq_util::subkey_by_type(key, &policy, KeyType::Decryption)?;
                let sig = sq_util::subkey_by_type(key, &policy, KeyType::Signing)?;

                admin.upload_key(cert, KeyType::Authentication, None)?;

                if let Some(dec) = dec {
                    admin.upload_key(dec, KeyType::Decryption, None)?;
                }
                if let Some(sig) = sig {
                    admin.upload_key(sig, KeyType::Signing, None)?;
                }

                admin.set_name("OpenPGP CA")?;

                let new_pin = set_user_and_admin_pin(&mut admin, PW3_DEFAULT)?;
                Ok(new_pin)
            }
            0 => Err(anyhow::anyhow!("No certification capable key found in key")),

            _ => Err(anyhow::anyhow!(
                "More than one certification capable key found in key"
            )),
        }
    } else {
        Err(anyhow!("Failed to open card in admin mode."))
    }
}

/// Given the current `admin_pin`, set both the User and Admin PIN to a new random 8-digit value
/// (the new PIN gets returned)
fn set_user_and_admin_pin(card: &mut Card<Admin>, admin_pin: &str) -> Result<String> {
    // Generate new 8-digit random PIN
    let new_pin = random_user_pin();

    // Set Admin PIN to new_pin.
    // (This undoes the previous Admin PIN verification, at least on some cards)
    card.as_open()
        .change_admin_pin(admin_pin.as_bytes(), new_pin.as_bytes())?;

    // Re-Verify with new Admin PIN (otherwise admin access privileges are missing)
    card.as_open().verify_admin(new_pin.as_bytes())?;

    // Set new User PIN
    card.reset_user_pin(new_pin.as_bytes())?;

    // Note: on Gnuk, the User and Admin PIN are now "separated" (changing one doesn't
    // implicitly change the other anymore). However, they are set to the same value.

    Ok(new_pin)
}

/// Generate a random 8 digit String to use as User/Admin PIN
fn random_user_pin() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let i: u64 = rng.gen_range(0..=99_999_999);
    format!("{:08}", i)
}

/// Test if the card accepts `pin` as User PIN
pub(crate) fn verify_user_pin(ident: &str, pin: &str) -> Result<()> {
    let backend = PcscBackend::open_by_ident(ident, None)?;
    let mut card: Card<Open> = backend.into();
    let mut transaction = card.transaction()?;

    transaction.verify_user(pin.as_bytes())?;

    Ok(())
}
