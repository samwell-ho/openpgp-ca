// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::ca::OpenpgpCa;
use crate::db::models;
use crate::pgp::Pgp;

use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::types::ReasonForRevocation;
use sequoia_openpgp::{Cert, Packet};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use diesel::prelude::*;

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Initialize OpenPGP CA Admin database entry.
///
/// This generates a new OpenPGP Key for the Admin role and stores the
/// private Key in the OpenPGP CA database.
///
/// `domainname` is the domain that this CA Admin is in charge of,
/// `name` is a descriptive name for the CA Admin
///
/// Only one CA Admin can be configured per database.
pub fn ca_init(
    oca: &OpenpgpCa,
    domainname: &str,
    name: Option<&str>,
) -> Result<()> {
    if oca.db().get_ca()?.is_some() {
        return Err(anyhow::anyhow!("ERROR: CA has already been created",));
    }

    // domainname syntax check
    if !publicsuffix::Domain::has_valid_syntax(domainname) {
        return Err(anyhow::anyhow!("Parameter is not a valid domainname",));
    }

    let name = match name {
        Some(name) => Some(name),
        _ => Some("OpenPGP CA"),
    };

    let (cert, _) = Pgp::make_ca_cert(domainname, name)?;

    let ca_key = &Pgp::cert_to_armored_private_key(&cert)?;

    oca.db().get_conn().transaction::<_, anyhow::Error, _>(|| {
        oca.db().insert_ca(
            models::NewCa { domainname },
            ca_key,
            &cert.fingerprint().to_hex(),
        )?;

        Ok(())
    })
}

/// Get a sequoia `Cert` object for the CA from the database.
///
/// This is the OpenPGP Cert of the CA.
pub fn ca_get_cert(oca: &OpenpgpCa) -> Result<Cert> {
    match oca.db().get_ca()? {
        Some((_, cert)) => Ok(Pgp::armored_to_cert(&cert.priv_cert)?),
        _ => panic!("get_ca_cert() failed"),
    }
}

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
pub fn ca_generate_revocations(
    oca: &OpenpgpCa,
    output: PathBuf,
) -> Result<()> {
    let ca = oca.ca_get_cert()?;

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
            format!("Hard revocation (certificate compromised) ({})", date),
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

/// get the email of this CA
pub fn get_ca_email(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let uids: Vec<_> = cert.userids().collect();

    if uids.len() != 1 {
        return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
    }

    let email = &uids[0].userid().email()?;

    if let Some(email) = email {
        Ok(email.clone())
    } else {
        Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
    }
}

/// get the domainname of this CA
pub fn get_ca_domain(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let uids: Vec<_> = cert.userids().collect();

    if uids.len() != 1 {
        return Err(anyhow::anyhow!("ERROR: CA has != 1 user_id"));
    }

    let email = &uids[0].userid().email()?;

    if let Some(email) = email {
        let split: Vec<_> = email.split('@').collect();

        if split.len() == 2 {
            Ok(split[1].to_owned())
        } else {
            Err(anyhow::anyhow!(
                "ERROR: Error while splitting domain from CA user_id "
            ))
        }
    } else {
        Err(anyhow::anyhow!("ERROR: CA user_id has no email"))
    }
}

/// Returns the public key of the CA as an armored String
pub fn ca_get_pubkey_armored(oca: &OpenpgpCa) -> Result<String> {
    let cert = oca.ca_get_cert()?;
    let ca_pub = Pgp::cert_to_armored(&cert)
        .context("failed to transform CA key to armored pubkey")?;

    Ok(ca_pub)
}

/// Add trust-signature(s) from CA users to the CA's Cert.
///
/// This receives an armored version of the CA's public key, finds
/// any trust-signatures on it and merges those into "our" local copy of
/// the CA key.
pub fn ca_import_tsig(oca: &OpenpgpCa, cert: &str) -> Result<()> {
    oca.db().get_conn().transaction::<_, anyhow::Error, _>(|| {
        let ca_cert = oca.ca_get_cert().unwrap();

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
        let (_, mut ca_cert) = oca
            .db()
            .get_ca()
            .context("failed to load CA from database")?
            .unwrap();

        ca_cert.priv_cert = Pgp::cert_to_armored_private_key(&signed)
            .context("failed to armor CA Cert")?;

        oca.db()
            .update_cacert(&ca_cert)
            .context("Update of CA Cert in DB failed")?;

        Ok(())
    })
}
