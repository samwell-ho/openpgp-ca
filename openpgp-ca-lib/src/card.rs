// SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::{anyhow, Result};
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::{KeyType, OpenPgp};

use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::sq_util;
use openpgp_card_sequoia::util::{make_cert, public_key_material_to_key};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

// The default Admin PIN for a factory reset card.
// We assume that we start unconfigured cards for setting up card-based CAs,
// so we assume the default Admin PIN can be used.
const PW3_DEFAULT: &str = "12345678";

/// Check if the card `ident` is empty.
/// The card is considered empty when fingerprints for all three keyslots are unset.
fn check_card_empty(open: &Open) -> Result<bool> {
    let fps = open.fingerprints()?;
    if fps.signature() != None || fps.decryption() != None || fps.authentication() != None {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Generate a new certification key on the card, return its public key representation.
///
/// Expects Admin PIN to be set to the default value of `12345678`.
/// During card setup, this fn resets the User PIN to a new, random, 8 digit value.
pub(crate) fn generate_on_card(ident: &str, user_id: String) -> Result<(Cert, String)> {
    let mut card = PcscBackend::open_by_ident(ident, None)?;
    let mut pgp = OpenPgp::new(&mut card);
    let mut open = Open::new(pgp.transaction()?)?;

    // check that card has no keys on it
    if !check_card_empty(&open)? {
        return Err(anyhow!(
            "The OpenPGP card contains key material, please reset it before use with OpenPGP CA."
        ));
    }

    // FIXME: make dynamic? (we want to use rsa4k by default, but Gnuk can't generate rsa4k)
    let algo = Some(AlgoSimple::Curve25519);

    // We assume that the default Admin PIN is currently valid
    if open.verify_admin(PW3_DEFAULT.as_bytes()).is_err() {
        return Err(anyhow!(
            "Failed to get Admin access to the card with the default PIN."
        ));
    };

    if let Ok(mut admin) = open
        .admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access"))
    {
        println!(" Generate subkey for Signing");
        let (pkm, ts) = admin.generate_key_simple(KeyType::Signing, algo)?;
        admin.set_name("OpenPGP CA")?;

        let key_sig = public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None)?;

        // change User PIN
        //
        // NOTE: This is done after key generation because Gnuk doesn't allow PIN changes
        // when the card contains no keys.
        //
        // NOTE: with Gnuk, this PIN also serves as the new Admin PIN, by default!
        let new_user_pin = random_user_pin();

        admin.reset_user_pin(new_user_pin.as_bytes())?;

        let cert = make_cert(
            &mut open,
            key_sig,
            None,
            None,
            Some(new_user_pin.as_bytes()),
            &|| println!("Enter User PIN on card reader pinpad."),
            &|| println!("Need touch confirmation for signing."),
            &[user_id],
        )?;

        Ok((cert, new_user_pin))
    } else {
        Err(anyhow!("Failed to open card in admin mode."))
    }
}

/// Returns newly set User PIN
pub(crate) fn import_to_card(ident: &str, key: &Cert) -> Result<String> {
    let mut card = PcscBackend::open_by_ident(ident, None)?;
    let mut pgp = OpenPgp::new(&mut card);
    let mut open = Open::new(pgp.transaction()?)?;

    // check that card has no keys on it
    if !check_card_empty(&open)? {
        return Err(anyhow!(
            "The OpenPGP card contains key material, please reset it before use with OpenPGP CA."
        ));
    }

    open.verify_admin(PW3_DEFAULT.as_bytes())?;

    if let Ok(mut admin) = open
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
                let sig = certifier.pop().unwrap();
                let dec = sq_util::subkey_by_type(key, &policy, KeyType::Decryption)?;

                println!("Uploading {} as signing key", sig.fingerprint());
                admin.upload_key(sig, KeyType::Signing, None)?;

                if let Some(dec) = dec {
                    println!("Uploading {} as decryption key", dec.fingerprint());
                    admin.upload_key(dec, KeyType::Decryption, None)?;
                }

                admin.set_name("OpenPGP CA")?;

                let new_user_pin = random_user_pin();
                admin.reset_user_pin(new_user_pin.as_bytes())?;

                Ok(new_user_pin)
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

/// Generate a random 8 digit String to use as User PIN
fn random_user_pin() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let i: u64 = rng.gen_range(0..=99_999_999);
    format!("{:08}", i)
}
