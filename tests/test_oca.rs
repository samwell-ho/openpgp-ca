// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio_core::reactor::Core;

use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::KeyHandle;
use openpgp::{Cert, Fingerprint, KeyID};
use sequoia_openpgp as openpgp;

use openpgp_ca_lib::ca::OpenpgpCa;
use sequoia_openpgp::packet::signature::SignatureBuilder;

pub mod gnupg;

#[test]
/// Creates a CA (with a custom name) and a user.
///
/// Checks that CA (with custom name) and one user (with one revocation) are
/// visible via CA API.
fn test_ca() -> Result<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", Some("Example Org OpenPGP CA Key"))?;

    // make CA user
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let cert = &certs[0];
    let emails = ca.emails_get(cert)?;

    assert_eq!(emails.len(), 1);

    let revocs = ca.revocations_get(cert)?;
    assert_eq!(revocs.len(), 1);

    // check that the custom name has ended up in the CA Cert
    let ca_cert = ca.ca_get_cert().unwrap();
    let uid = ca_cert.userids().find(|c| {
        c.clone()
            .with_policy(&StandardPolicy::new(), None)
            .unwrap()
            .userid()
            .name()
            .unwrap()
            == Some("Example Org OpenPGP CA Key".to_owned())
    });

    assert!(uid.is_some());

    Ok(())
}

#[test]
/// Create a CA, then externally create a user cert and import it.
/// Check that the expiry of that cert is as expected.
///
/// Update the user cert externally (set later expiration).
/// Re-Import the user cert, check that the CA API still shows only one
/// user cert (i.e. an update took place, as opposed to a new user got
/// created).
/// Check that the updated user cert has the expected expiry duration.
///
/// This test also exercises the OpenpgpCa::certs_expired() function.
fn test_update_cert_key() -> Result<()> {
    let policy = StandardPolicy::new();

    let now = SystemTime::now();
    let in_one_year = now.checked_add(Duration::from_secs(3600 * 24 * 365));
    let in_three_years =
        now.checked_add(Duration::from_secs(3600 * 24 * 365 * 3));
    let in_six_years =
        now.checked_add(Duration::from_secs(3600 * 24 * 365 * 6));

    // update key with new version, but same fingerprint
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // import key as new user
    gnupg::create_user(&ctx, "alice@example.org");
    let alice1_key = gnupg::export(&ctx, &"alice@example.org");

    ca.cert_import_new(
        &alice1_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // check the state of CA data
    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let alice = &certs[0];

    // check that expiry is ~2y
    let cert = OpenpgpCa::cert_to_cert(alice)?;

    cert.with_policy(&policy, in_one_year)?.alive()?;
    assert!(cert.with_policy(&policy, in_three_years)?.alive().is_err());

    // check the same with ca.cert_expired()
    let exp1 = ca.certs_expired(365)?;
    assert_eq!(exp1.len(), 1);
    let (_, (alive, _)) = exp1.iter().next().unwrap();
    assert!(alive);

    let exp3 = ca.certs_expired(3 * 365).unwrap();
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(!alive);

    // edit key with gpg, then import new version into CA
    gnupg::edit_expire(&ctx, "alice@example.org", "5y")?;
    let alice2_key = gnupg::export(&ctx, &"alice@example.org");

    // get cert for alice
    let certs = ca.certs_get("alice@example.org")?;
    assert_eq!(certs.len(), 1);
    let _alice = &certs[0];

    // store updated version of cert
    ca.cert_import_update(&alice2_key)?;

    // check the state of CA data
    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = OpenpgpCa::cert_to_cert(&certs[0])?;

    assert!(cert.with_policy(&policy, in_three_years)?.alive().is_ok());
    assert!(!cert.with_policy(&policy, in_six_years)?.alive().is_ok());

    // check the same with ca.cert_expired()
    let exp3 = ca.certs_expired(3 * 365)?;
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(alive);

    let exp6 = ca.certs_expired(6 * 365)?;
    assert_eq!(exp6.len(), 1);
    let (_, (alive, _)) = exp6.iter().next().unwrap();
    assert!(!alive);

    Ok(())
}

#[test]
fn test_ca_import() -> Result<()> {
    // update key with new version, but same fingerprint
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // import key as new user
    gnupg::create_user(&ctx, "alice@example.org");
    let alice1_key = gnupg::export(&ctx, &"alice@example.org");

    ca.cert_import_new(
        &alice1_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // call "cert_import_new" again with the same key. this should be
    // cause an error, because no two certs with the same fingerprint can be
    // imported as distinct certs
    let res = ca.cert_import_new(
        &alice1_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    );

    assert!(res.is_err());

    // try to update the database cert entry with a different key.
    // this should cause an error, because updating a key is only allowed if
    // the fingerprint stays the same

    // make a new key
    gnupg::create_user(&ctx, "bob@example.org");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");

    // call "cert_import_update" with a new key

    // -> expect error, because this key doesn't exist in OpenPGP CA and
    // thus is not a legal update
    let res = ca.cert_import_update(&bob_key);
    assert!(res.is_err());

    Ok(())
}

#[test]
/// Create a new CA and two certs with the same email.
///
/// Expected outcome: two independent certs / users got created.
fn test_ca_insert_duplicate_email() -> Result<()> {
    // two certs with the same email are considered distinct certs
    // (e.g. "normal cert" vs "code signing cert")

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    assert!(ca.ca_init("example.org", None).is_ok());

    // make CA user
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;

    // make another CA user with the same email address
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 2);

    // ca cert should be tsigned by all user certs.
    for c in &certs {
        let tsig = ca.cert_check_tsig_on_ca(&c)?;
        assert!(tsig);
    }

    Ok(())
}

#[test]
/// create a CA for "example.org" and three users.
/// two of these users have emails in the "example.org" domain, the third
/// doesn't.
/// Export CA to wkd.
///
/// Expected outcome: the WKD contains three keys (CA + 2x user).
/// Check that the expected filenames exist in the WKD data.
fn test_ca_export_wkd() -> Result<()> {
    let ctx = gnupg::make_context()?;
    // ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    ca.ca_init("example.org", None)?;
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;
    ca.user_new(Some(&"Bob"), &["bob@example.org", "bob@other.org"], false)?;
    ca.user_new(Some(&"Carol"), &["carol@other.org"], false)?;

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.wkd_export("example.org", &wkd_path)?;

    // expect 3 exported keys (carol should not be in the export)
    let test_path = wkd_path.join(".well-known/openpgpkey/example.org/hu/");
    let paths: Vec<_> = fs::read_dir(test_path)?.collect();
    assert_eq!(paths.len(), 3);

    // check that both user keys have been written to files
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/jycbiujnsxs47xrkethgtj69xuunurok",
    );
    assert!(test_path.is_file());

    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/kei1q4tipxxu1yj79k9kfukdhfy631xe",
    );
    assert!(test_path.is_file());

    // check that CA key has been written to file
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /hu/ermf4k8pujzwtqqxmskb7355sebj5e4t",
    );
    assert!(test_path.is_file());

    // check that a policy file been created
    let test_path = wkd_path.join(
        ".well-known/openpgpkey/example.org\
         /policy",
    );
    assert!(test_path.is_file());

    Ok(())
}

#[test]
#[ignore]
/// Get sequoia-pgp.org keys for Justus and Neal from Hagrid.
/// Import into a fresh CA instance, then export as WKD.
fn test_ca_export_wkd_sequoia() -> Result<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());

    // -- get keys from hagrid

    let c = sequoia_core::Context::new()?;

    let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(&c)?;

    let mut core = Core::new()?;

    let j: Fingerprint = "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse()?;
    let justus: Cert = core.run(hagrid.get(&KeyID::from(j)))?;
    let justus_key = OpenpgpCa::cert_to_armored(&justus)?;

    let n: Fingerprint = "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?;
    let neal: Cert = core.run(hagrid.get(&KeyID::from(n)))?;
    let neal_key = OpenpgpCa::cert_to_armored(&neal)?;

    // -- import keys into CA

    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    ca.ca_init("sequoia-pgp.org", None)?;

    ca.cert_import_new(
        &justus_key,
        vec![],
        None,
        &["justus@sequoia-pgp.org"],
    )?;
    ca.cert_import_new(&neal_key, vec![], None, &["neal@sequoia-pgp.org"])?;

    // -- export as WKD

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.wkd_export("sequoia-pgp.org", &wkd_path)?;

    Ok(())
}

#[test]
/// Create a CA instance. Externally create a user cert and two revocations.
/// Import user cert and both revocations.
///
/// Check that CA API shows one cert with two revocations.
fn test_ca_multiple_revocations() -> Result<()> {
    // create two different revocation certificates for one key and import them

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // gpg: make key for Alice
    gnupg::create_user(&ctx, "Alice <alice@example.org>");

    let alice_key = gnupg::export(&ctx, &"alice@example.org");

    ca.cert_import_new(&alice_key, vec![], None, &[])?;

    // make two different revocation certificates and import them into the CA
    let revoc_file1 = format!("{}/alice.revoc1", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file1, 1)?;

    let revoc_file3 = format!("{}/alice.revoc3", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file3, 3)?;

    ca.revocation_add(&PathBuf::from(revoc_file1))?;
    ca.revocation_add(&PathBuf::from(revoc_file3))?;

    // check data in CA
    let certs = ca.user_certs_get_all()?;

    // check that name/email has been autodetected on CA import from the pubkey
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    let name = ca.cert_get_name(&alice)?;
    assert_eq!(name, "Alice".to_string());

    let emails = ca.emails_get(alice)?;
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].addr, "alice@example.org");

    // check for both revocation certs
    let revocs = ca.revocations_get(alice)?;

    assert_eq!(revocs.len(), 2);

    Ok(())
}

#[test]
/// Create new CA. Set up three users:
/// - Alice is imported, and signed by the CA key
/// - Bob is imported, but not signed by the CA key
/// - Carol is created with OpenPGP CA, so their cert is signed by and tsigns
///   the CA cert.
///
/// Check the output of OpenpgpCa::certs_check_signatures().
/// Expected:
/// - Alice is signed but hasn't tsigned the CA,
/// - Bob is not signed and hasn't tsigned the CA,
/// - Carol is signed and has tsigned the CA.
fn test_ca_signatures() -> Result<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;
    ca.ca_init("example.org", None)?;

    // create/import alice, CA signs alice's key
    gnupg::create_user(&ctx, "alice@example.org");
    let alice_key = gnupg::export(&ctx, &"alice@example.org");

    ca.cert_import_new(
        &alice_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice to CA failed")?;

    // create/import bob
    gnupg::create_user(&ctx, "bob@example.org");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");

    // CA does not signs bob's key because the "email" parameter is empty.
    // Only userids that are supplied in `email` are signed by the CA.
    ca.cert_import_new(&bob_key, vec![], Some("Bob"), &[])
        .context("import Bob to CA failed")?;

    // create carol, CA will sign carol's key.
    // also, CA key gets a tsig by carol
    ca.user_new(Some(&"Carol"), &["carol@example.org"], false)?;

    for user in ca.users_get_all()? {
        let certs = ca.get_certs_by_user(&user)?;

        let name = user.name.unwrap_or_else(|| "<no name>".to_owned());

        assert_eq!(certs.len(), 1);

        let (sig_from_ca, tsig_on_ca) =
            ca.cert_check_certifications(&certs[0])?;

        match name.as_str() {
            "Alice" => {
                assert!(sig_from_ca);
                assert!(!tsig_on_ca);
            }
            "Bob" => {
                assert!(!sig_from_ca);
                assert!(!tsig_on_ca);
            }
            "Carol" => {
                assert!(sig_from_ca);
                assert!(tsig_on_ca);
            }
            _ => panic!(),
        }
    }

    Ok(())
}

#[test]
/// Create a CA and a user. Apply the user's revocation.
///
/// Check that the revocation has been published to the user's cert.
fn test_apply_revocation() -> Result<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;
    ca.ca_init("example.org", None)?;

    // make CA user
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let alice = &certs[0];

    let rev = ca.revocations_get(alice)?;
    assert_eq!(rev.len(), 1);

    ca.revocation_apply(rev[0].clone())?;

    let rev = ca.revocations_get(alice)?;
    assert_eq!(rev.len(), 1);
    assert!(rev.get(0).unwrap().published);

    Ok(())
}

#[test]
/// Create a CA. Create a user cert externally that is already signed by
/// the CA key. Import this already signed key.
///
/// Check that the imported key only has one signature.
fn test_import_signed_cert() -> Result<()> {
    let policy = StandardPolicy::new();

    let ctx = gnupg::make_context()?;
    // ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;
    ca.ca_init("example.org", None)?;

    // import CA key into GnuPG
    let ca_cert = ca.ca_get_cert()?;
    let mut buf = Vec::new();
    ca_cert.as_tsk().serialize(&mut buf)?;
    gnupg::import(&ctx, &buf);

    // set up, sign Alice key with gnupg
    gnupg::create_user(&ctx, "Alice <alice@example.org>");
    gnupg::sign(&ctx, "alice@example.org").expect("signing alice failed");

    // import alice into OpenPGP CA
    let alice_key = gnupg::export(&ctx, &"alice@example.org");
    ca.cert_import_new(
        &alice_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    )?;

    // get alice cert back from CA
    let certs = ca.certs_get("alice@example.org")?;
    assert_eq!(certs.len(), 1);

    let alice = &certs[0];
    let cert = OpenpgpCa::cert_to_cert(&alice)?;

    assert_eq!(cert.userids().len(), 1);

    // check number of signatures on alice userids
    for uid in cert.userids() {
        let sigs = uid.with_policy(&policy, None)?.bundle().certifications();

        assert_eq!(
            sigs.len(),
            1,
            "alice should have one third party certification (per uid)"
        );
    }

    // check signature status via OpenpgpCa::certs_check_signatures()
    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let (sig_from_ca, tsig_on_ca) = ca.cert_check_certifications(&certs[0])?;

    let name = ca.cert_get_name(&certs[0])?;
    match name.as_str() {
        "Alice" => {
            assert!(sig_from_ca);
            assert!(!tsig_on_ca);
        }
        _ => panic!(),
    }

    Ok(())
}

#[test]
/// Create a new CA, add two users.
/// Then import a revocation certificate without an issuer_fingerprint.
/// (The certificate only has a KeyID)
///
/// OpenPGP CA needs to match this revocation to the correct cert.
///
/// Check that the user certs have the expected number of revocations
/// associated.
fn test_revocation_no_fingerprint() -> Result<()> {
    // create two different revocation certificates for one key and import them

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // create Alice
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;

    // gpg: make key for Bob
    gnupg::create_user(&ctx, "Bob <bob@example.org>");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");
    ca.cert_import_new(&bob_key, vec![], None, &[])?;

    // make a revocation certificate for bob ...
    let revoc_file = format!("{}/bob.revoc", home_path);
    gnupg::make_revocation(&ctx, "bob@example.org", &revoc_file, 1)?;

    // ... remove the issuer fingerprint ...
    let p = openpgp::Packet::from_file(&revoc_file)
        .context("Input could not be parsed")?;

    let armored = if let openpgp::Packet::Signature(s) = p {
        // modify Signature: remove IssuerFingerprint subpacket

        let b: SignatureBuilder = s.into();

        // use Bob as a Signer
        let bob_sec = gnupg::export_secret(&ctx, &"bob@example.org");
        let bob_cert = Cert::from_bytes(&bob_sec)?;
        let mut keypair = bob_cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        // wait for a second before making a new signature -
        // two signatures with the same timestamp are not allowed
        std::thread::sleep(std::time::Duration::from_millis(1_000));

        let mut sig =
            b.sign_direct_key(&mut keypair, &bob_cert.primary_key())?;

        sig.unhashed_area_mut()
            .remove_all(SubpacketTag::IssuerFingerprint);

        // assert that sig has no KeyHandle::Fingerprint in its issuers
        assert!(!sig
            .get_issuers()
            .iter()
            .any(|kh| { matches!(kh, KeyHandle::Fingerprint(_)) }));

        OpenpgpCa::sig_to_armored(&sig)
            .context("couldn't armor revocation cert")?
    } else {
        panic!("Error handling Signature Packet");
    };

    println!("revocation bob: {}", &armored);

    // save in file
    std::fs::write(&revoc_file, &armored)?;

    // ... and import into the CA
    ca.revocation_add(&PathBuf::from(&revoc_file))
        .context("Storing Bob's revocation in OpenPGP CA")?;

    //
    // -- check data in CA --
    let certs = ca.user_certs_get_all()?;

    let alice = certs
        .iter()
        .find(|c| {
            ca.cert_get_users(&c)
                .unwrap()
                .iter()
                .any(|u| u.name == Some("Alice".to_owned()))
        })
        .unwrap();
    let alice_revs = ca.revocations_get(alice)?;
    assert_eq!(alice_revs.len(), 1, "Revocation generated by OpenPGP CA");

    println!("revocation alice: {}", &alice_revs[0].revocation);

    let bob = certs
        .iter()
        .find(|c| {
            ca.cert_get_users(&c)
                .unwrap()
                .iter()
                .any(|u| u.name == Some("Bob".to_owned()))
        })
        .unwrap();
    let bob_revs = ca.revocations_get(bob)?;
    assert_eq!(bob_revs.len(), 1, "Revocation without issuer fingerprint");

    Ok(())
}

#[test]
/// Create a CA and a user with password.
///
/// Check that the CA admin key is signed by the user (even with password
/// encrypted user key)
fn test_create_user_with_pw() -> Result<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;
    ca.ca_init("example.org", None)?;

    // make CA user
    ca.user_new(Some(&"Alice"), &["alice@example.org"], true)?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    Ok(())
}
