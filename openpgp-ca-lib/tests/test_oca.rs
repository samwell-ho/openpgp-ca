// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use openpgp_ca_lib::pgp;
use openpgp_ca_lib::{OpenpgpCa, OpenpgpCaUninit};
use rusqlite::Connection;
use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::packet::signature::subpacket::{Subpacket, SubpacketTag, SubpacketValue};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, KeyID, Packet};

#[test]
/// Creates a CA (with a custom name) and a user.
///
/// Checks that CA (with custom name) and one user (with one revocation) are
/// visible via CA API.
fn test_ca() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", Some("Example Org OpenPGP CA Key"))?;

    // make CA user
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let cert = &certs[0];
    let emails = ca.emails_get(cert)?;

    assert_eq!(emails.len(), 1);

    let revocs = ca.revocations_get(cert)?;
    assert_eq!(revocs.len(), 1);

    // check that the custom name has ended up in the CA Cert
    let ca_cert = ca.ca_get_cert_pub().unwrap();
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
/// Creates a CA and a user. The certification for the user is valid for
/// 365 days only.
///
/// Checks that the certification indeed has a limited validity.
fn test_expiring_certification() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", Some("Example Org OpenPGP CA Key"))?;

    let ca_cert = ca.ca_get_cert_pub()?;
    let ca_fp = ca_cert.fingerprint();

    // make CA user
    ca.user_new(
        Some("Alice"),
        &["alice@example.org"],
        Some(365),
        false,
        false,
    )?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let c = pgp::to_cert(cert.pub_cert.as_bytes())?;

    // alice should have one user id
    assert_eq!(c.userids().len(), 1);

    let uid = c.userids().last().unwrap();

    let certs: Vec<_> = uid.certifications().collect();
    assert_eq!(certs.len(), 1);

    let ca_certification = &certs[0];

    // is this certification really from our CA?
    assert_eq!(
        *ca_certification.issuer_fingerprints().last().unwrap(),
        ca_fp
    );

    let validity = ca_certification.signature_validity_period();

    assert!(validity.is_some());
    let days = validity.unwrap().as_secs() / 60 / 60 / 24;

    // check that the certification by the CA is valid for ~365 days
    assert!((364..=366).contains(&days));

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
    let in_three_years = now.checked_add(Duration::from_secs(3600 * 24 * 365 * 3));
    let in_six_years = now.checked_add(Duration::from_secs(3600 * 24 * 365 * 6));

    // update key with new version, but same fingerprint
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", None)?;

    // import key as new user
    gpg.create_user("Alice <alice@example.org>");
    let alice1_key = gpg.export("alice@example.org");

    ca.cert_import_new(
        alice1_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    )
    .context("import Alice 1 to CA failed")?;

    // check the state of CA data
    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    let alice = &certs[0];

    // check that expiry is ~2y
    let cert = pgp::to_cert(alice.pub_cert.as_bytes())?;

    cert.with_policy(&policy, in_one_year)?.alive()?;
    assert!(cert.with_policy(&policy, in_three_years)?.alive().is_err());

    // check the same with ca.cert_expired()
    let exp1 = ca.certs_expired(365)?;
    assert_eq!(exp1.len(), 0);

    let exp3 = ca.certs_expired(3 * 365).unwrap();
    assert_eq!(exp3.len(), 1);

    // edit key with gpg, then import new version into CA
    gpg.edit_expire("alice@example.org", "5y")?;
    let alice2_key = gpg.export("alice@example.org");

    // get cert for alice
    let certs = ca.certs_by_email("alice@example.org")?;
    assert_eq!(certs.len(), 1);
    let _alice = &certs[0];

    // store updated version of cert
    ca.cert_import_update(alice2_key.as_bytes())?;

    // check the state of CA data
    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = pgp::to_cert(certs[0].pub_cert.as_bytes())?;

    assert!(cert.with_policy(&policy, in_three_years)?.alive().is_ok());
    assert!(cert.with_policy(&policy, in_six_years)?.alive().is_err());

    // check the same with ca.cert_expired()
    let exp3 = ca.certs_expired(3 * 365)?;
    assert_eq!(exp3.len(), 0);

    let exp6 = ca.certs_expired(6 * 365)?;
    assert_eq!(exp6.len(), 1);

    Ok(())
}

#[test]
fn test_ca_import() -> Result<()> {
    // update key with new version, but same fingerprint
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", None)?;

    // import key as new user
    gpg.create_user("Alice <alice@example.org>");
    let alice1_key = gpg.export("alice@example.org");

    ca.cert_import_new(
        alice1_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    )
    .context("import Alice 1 to CA failed")?;

    // call "cert_import_new" again with the same key. this should be
    // cause an error, because no two certs with the same fingerprint can be
    // imported as distinct certs
    let res = ca.cert_import_new(
        alice1_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    );

    assert!(res.is_err());

    // try to update the database cert entry with a different key.
    // this should cause an error, because updating a key is only allowed if
    // the fingerprint stays the same

    // make a new key
    gpg.create_user("Bob <bob@example.org>");
    let bob_key = gpg.export("bob@example.org");

    // call "cert_import_update" with a new key

    // -> expect error, because this key doesn't exist in OpenPGP CA and
    // thus is not a legal update
    let res = ca.cert_import_update(bob_key.as_bytes());
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

    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", None)?;

    // make CA user
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    // make another CA user with the same email address
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    let certs = ca.user_certs_get_all()?;

    assert_eq!(certs.len(), 2);

    // ca cert should be tsigned by all user certs.
    for c in &certs {
        let tsig = ca.cert_check_tsig_on_ca(c)?;
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
    let gpg = gnupg_test_wrapper::make_context()?;
    // gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;
    ca.user_new(
        Some("Bob"),
        &["bob@example.org", "bob@other.org"],
        None,
        false,
        false,
    )?;
    ca.user_new(Some("Carol"), &["carol@other.org"], None, false, false)?;

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("example.org", wkd_path)?;

    // expect 3 exported keys (carol should not be in the export)
    let test_path = wkd_path.join(".well-known/openpgpkey/example.org/hu/");
    let paths = fs::read_dir(test_path)?;
    assert_eq!(paths.count(), 3);

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
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());

    // -- get keys from hagrid

    use tokio::runtime::Runtime;
    let rt = Runtime::new()?;

    let j: Fingerprint = "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse()?;
    let justus: Cert = rt.block_on(async move {
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(sequoia_net::Policy::Encrypted)?;
        hagrid.get(&KeyID::from(j)).await
    })?;
    let justus_key = pgp::cert_to_armored(&justus)?;

    let n: Fingerprint = "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?;
    let neal: Cert = rt.block_on(async move {
        let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(sequoia_net::Policy::Encrypted)?;
        hagrid.get(&KeyID::from(n)).await
    })?;
    let neal_key = pgp::cert_to_armored(&neal)?;

    // -- import keys into CA

    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("sequoia-pgp.org", None)?;

    ca.cert_import_new(
        justus_key.as_bytes(),
        &[],
        None,
        &["justus@sequoia-pgp.org"],
        None,
    )?;
    ca.cert_import_new(
        neal_key.as_bytes(),
        &[],
        None,
        &["neal@sequoia-pgp.org"],
        None,
    )?;

    // -- export as WKD

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("sequoia-pgp.org", wkd_path)?;

    Ok(())
}

#[test]
/// Create a CA instance. Externally create a user cert and two revocations.
/// Import user cert and both revocations.
///
/// Check that CA API shows one cert with two revocations.
fn test_ca_multiple_revocations() -> Result<()> {
    // create two different revocation certificates for one key and import them

    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", None)?;

    // gpg: make key for Alice
    gpg.create_user("Alice <alice@example.org>");

    let alice_key = gpg.export("alice@example.org");

    ca.cert_import_new(
        alice_key.as_bytes(),
        &[],
        None,
        &["alice@example.org"],
        None,
    )?;

    // make two different revocation certificates and import them into the CA
    let revoc_file1 = format!("{}/alice.revoc1", home_path);
    gpg.make_revocation("alice@example.org", &revoc_file1, 1)?;

    let revoc_file3 = format!("{}/alice.revoc3", home_path);
    gpg.make_revocation("alice@example.org", &revoc_file3, 3)?;

    ca.revocation_add_from_file(&PathBuf::from(revoc_file1))?;
    ca.revocation_add_from_file(&PathBuf::from(revoc_file3))?;

    // check data in CA
    let certs = ca.user_certs_get_all()?;

    // email has been explcitly set for CA import from the pubkey
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    // check that name has been autodetected on CA import from the pubkey
    let name = ca.cert_get_name(alice)?;
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
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    // create/import alice, CA signs alice's key
    gpg.create_user("Alice <alice@example.org>");
    let alice_key = gpg.export("alice@example.org");

    ca.cert_import_new(
        alice_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    )
    .context("import Alice to CA failed")?;

    // create/import bob
    gpg.create_user("Bob <bob@example.org>");
    let bob_key = gpg.export("bob@example.org");

    // CA does not signs bob's key because the "email" parameter is empty.
    // Only userids that are supplied in `email` are signed by the CA.
    ca.cert_import_new(bob_key.as_bytes(), &[], Some("Bob"), &[], None)
        .context("import Bob to CA failed")?;

    // create carol, CA will sign carol's key.
    // also, CA key gets a tsig by carol
    ca.user_new(Some("Carol"), &["carol@example.org"], None, false, false)?;

    for user in ca.users_get_all()? {
        let certs = ca.get_certs_by_user(&user)?;

        let name = user.name.unwrap_or_else(|| "<no name>".to_owned());

        assert_eq!(certs.len(), 1);

        let sig_from_ca = ca.cert_check_ca_sig(&certs[0])?;
        let tsig_on_ca = ca.cert_check_tsig_on_ca(&certs[0])?;

        match name.as_str() {
            "Alice" => {
                assert!(!sig_from_ca.certified.is_empty());
                assert!(!tsig_on_ca);
            }
            "Bob" => {
                assert!(sig_from_ca.certified.is_empty());
                assert!(!tsig_on_ca);
            }
            "Carol" => {
                assert!(!sig_from_ca.certified.is_empty());
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
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    // make CA user
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

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

    let gpg = gnupg_test_wrapper::make_context()?;
    // gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    // import CA key into GnuPG
    let sqlite = Connection::open(db)?;
    //   grab CA key directly from sqlite db for this test
    let ca_private: String = sqlite
        .query_row("SELECT priv_cert FROM cacerts", &[], |row| row.get(0))
        .unwrap();

    gpg.import(ca_private.as_bytes());

    // set up, sign Alice key with gnupg
    gpg.create_user("Alice <alice@example.org>");
    gpg.sign("alice@example.org").expect("signing alice failed");

    // import alice into OpenPGP CA
    let alice_key = gpg.export("alice@example.org");
    ca.cert_import_new(
        alice_key.as_bytes(),
        &[],
        Some("Alice"),
        &["alice@example.org"],
        None,
    )?;

    // get alice cert back from CA
    let certs = ca.certs_by_email("alice@example.org")?;
    assert_eq!(certs.len(), 1);

    let alice = &certs[0];
    let cert = pgp::to_cert(alice.pub_cert.as_bytes())?;

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

    let sig_from_ca = ca.cert_check_ca_sig(&certs[0])?;
    let tsig_on_ca = ca.cert_check_tsig_on_ca(&certs[0])?;

    let name = ca.cert_get_name(&certs[0])?;
    match name.as_str() {
        "Alice" => {
            assert!(!sig_from_ca.certified.is_empty());
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

    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;

    // make new CA key
    let ca = cau.ca_init_softkey("example.org", None)?;

    // create Alice
    ca.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    // gpg: make key for Bob
    gpg.create_user("Bob <bob@example.org>");
    let bob_key = gpg.export("bob@example.org");
    ca.cert_import_new(bob_key.as_bytes(), &[], None, &[], None)?;

    // make a revocation certificate for bob ...
    let revoc_file = format!("{}/bob.revoc", home_path);
    gpg.make_revocation("bob@example.org", &revoc_file, 1)?;

    // ... remove the issuer fingerprint ...
    let p = Packet::from_file(&revoc_file).context("Input could not be parsed")?;

    let armored = if let Packet::Signature(s) = p {
        // use Bob as a Signer
        let bob_sec = gpg.export_secret("bob@example.org");
        let bob_cert = Cert::from_bytes(&bob_sec)?;
        let mut keypair = bob_cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        // modify Signature: remove IssuerFingerprint subpacket

        let mut b: SignatureBuilder = s.into();

        // Set the IssuerFingerprint (and Issuer) in the unhashed area.
        // Otherwise Sequoia will add them to the hashed area, and then we
        // can't remove them (below) without breaking the signature.
        b = b.modify_unhashed_area(|mut a| {
            a.add(Subpacket::new(
                SubpacketValue::IssuerFingerprint(bob_cert.fingerprint()),
                false,
            )?)?;
            a.add(Subpacket::new(
                SubpacketValue::Issuer(bob_cert.keyid()),
                false,
            )?)?;

            Ok(a)
        })?;

        // wait for a second before making a new signature -
        // two signatures with the same timestamp are not allowed
        std::thread::sleep(std::time::Duration::from_millis(1_000));

        let mut sig = b.sign_direct_key(&mut keypair, Some(bob_cert.primary_key().key()))?;

        sig.unhashed_area_mut()
            .remove_all(SubpacketTag::IssuerFingerprint);

        // assert that sig has no KeyHandle::Fingerprint in its issuers
        assert!(!sig
            .get_issuers()
            .iter()
            .any(|kh| { matches!(kh, KeyHandle::Fingerprint(_)) }));

        OpenpgpCa::revoc_to_armored(&sig).context("couldn't armor revocation cert")?
    } else {
        panic!("Error handling Signature Packet");
    };

    println!("revocation bob: {}", &armored);

    // save in file
    std::fs::write(&revoc_file, &armored)?;

    // ... and import into the CA
    ca.revocation_add_from_file(&PathBuf::from(&revoc_file))
        .context("Storing Bob's revocation in OpenPGP CA")?;

    //
    // -- check data in CA --
    let certs = ca.user_certs_get_all()?;

    let alice = certs
        .iter()
        .find(|c| {
            ca.cert_get_users(c)
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
            ca.cert_get_users(c)
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
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    // make CA user
    ca.user_new(Some("Alice"), &["alice@example.org"], None, true, false)?;

    let certs = ca.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);
    let alice = &certs[0];

    assert!(
        ca.cert_check_tsig_on_ca(alice)?,
        "CA cert is not signed by Alice"
    );

    Ok(())
}

#[test]
/// Create a CA and a number of users with certifications by the CA that
/// expire at different points.
///
/// Run a refresh and check if the results are as expected
fn test_refresh() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;
    //    gpg.leak_tempdir();

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    let ca_cert = ca.ca_get_cert_pub()?;
    let ca_fp = ca_cert.fingerprint();

    // make CA user
    ca.user_new(Some("Alice"), &["alice@example.org"], Some(10), true, false)?;
    ca.user_new(Some("Bob"), &["bob@example.org"], Some(365), true, false)?;
    ca.user_new(Some("Carol"), &["carol@example.org"], None, true, false)?;
    ca.user_new(Some("Dave"), &["dave@example.org"], Some(10), true, false)?;

    // set dave to "inactive"
    let cert = ca.certs_by_email("dave@example.org")?;
    assert_eq!(cert.len(), 1);
    let mut dave = cert[0].clone();
    dave.inactive = true;
    ca.db().cert_update(&dave)?;

    // refresh all CA certifications that are valid for less than 30 days
    ca.certs_refresh_ca_certifications(30, 365)?;

    let certs = ca.user_certs_get_all()?;
    for cert in certs {
        let u = ca.cert_get_users(&cert)?.unwrap();
        let c = pgp::to_cert(cert.pub_cert.as_bytes())?;

        // get all certifications from the CA
        assert_eq!(c.userids().len(), 1);
        let uid = c.userids().last().unwrap();
        let ca_sigs: Vec<_> = uid
            .certifications()
            .filter(|s| s.issuer_fingerprints().any(|fp| *fp == ca_fp))
            .collect();

        match u.name.unwrap().as_str() {
            "Alice" => {
                assert_eq!(ca_sigs.len(), 2);
                assert_eq!(
                    ca_sigs[0].signature_validity_period(),
                    Some(Duration::new(31536000, 0))
                );
                assert_eq!(
                    ca_sigs[1].signature_validity_period(),
                    Some(Duration::new(864000, 0))
                );
                assert!(!cert.inactive);
            }
            "Bob" => {
                assert_eq!(ca_sigs.len(), 1);
                assert!(!cert.inactive);
            }
            "Carol" => {
                assert_eq!(ca_sigs.len(), 1);
                assert!(!cert.inactive);
            }
            "Dave" => {
                assert_eq!(ca_sigs.len(), 1);
                assert_eq!(
                    ca_sigs[0].signature_validity_period(),
                    Some(Duration::new(864000, 0))
                );
                assert!(cert.inactive);
            }

            _ => panic!("unexpected cert found"),
        }
    }

    Ok(())
}

#[test]
/// Create a CA and two users. "delist" one user.
/// Export to WKD. Check that only the other user has been exported.
fn test_wkd_delist() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let cau = OpenpgpCaUninit::new(Some(&db))?;
    let ca = cau.ca_init_softkey("example.org", None)?;

    // make CA users
    ca.user_new(Some("Alice"), &["alice@example.org"], None, true, false)?;
    ca.user_new(Some("Bob"), &["bob@example.org"], None, true, false)?;

    // set bob to "delisted"
    let cert = ca.certs_by_email("bob@example.org")?;
    assert_eq!(cert.len(), 1);
    let mut bob = cert[0].clone();
    bob.delisted = true;
    ca.db().cert_update(&bob)?;

    // export to WKD
    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("example.org", wkd_path)?;

    // expect 3 exported keys (carol should not be in the export)
    let test_path = wkd_path.join(".well-known/openpgpkey/example.org/hu/");
    let paths = fs::read_dir(test_path)?;
    assert_eq!(paths.count(), 2);

    // check that Alice's and the CA's keys have been written to files

    // Alice
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
/// Create a CA with two users, one not certified by the CA.
///
/// Create a new CA, import the two users (with the certifications by the old CA key).
/// Re-certify with the new CA, check that certifications exist as expected
fn test_ca_re_certify() -> Result<()> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let home_path = String::from(gpg.get_homedir().to_str().unwrap());
    let db1 = format!("{}/ca1.sqlite", home_path);

    let ca1u = OpenpgpCaUninit::new(Some(&db1))?;

    // make first/old CA
    let ca1 = ca1u.ca_init_softkey("example.org", Some("example.org CA old"))?;

    // make CA user (certified by the CA)
    ca1.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    let (bob, _rev) = CertBuilder::new()
        .add_userid("Bob Baker <bob@example.org>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .generate()?;

    ca1.cert_import_new(pgp::cert_to_armored(&bob)?.as_bytes(), &[], None, &[], None)?;

    // make "new" CA
    let db2 = format!("{}/ca2.sqlite", home_path);
    let ca2u = OpenpgpCaUninit::new(Some(&db2))?;
    let ca2 = ca2u.ca_init_softkey("example.org", Some("example.org CA new"))?;

    // import certs from old CA, without certifying anything
    for cert in ca1.user_certs_get_all()? {
        ca2.cert_import_new(cert.pub_cert.as_bytes(), &[], None, &[], None)?;
    }

    // assert that no user id is certified at this point
    let certs = ca2.user_certs_get_all()?;
    assert_eq!(certs.len(), 2);

    let ca_cert = ca2.ca_get_cert_pub()?;

    for cert in certs.iter().map(|c| {
        pgp::to_cert(c.pub_cert.as_bytes()).expect("pub_cert should be convertible to a Cert")
    }) {
        for uid in cert.userids() {
            let ca_certifications = pgp::valid_certifications_by(&uid, &cert, ca_cert.clone());
            assert!(ca_certifications.is_empty());
        }
    }

    // re-certify
    ca2.ca_re_certify(ca1.ca_get_pubkey_armored()?.as_bytes(), 365)?;

    let ca_new_cert = ca2.ca_get_cert_pub()?;

    // get all certs
    let certs = ca2.user_certs_get_all()?;
    assert_eq!(certs.len(), 2);

    // FIXME: this relies on stable ordering of the certs, which is probably not guaranteed

    // assert that alice's userid is certified by the new CA
    let cert = pgp::to_cert(certs[0].pub_cert.as_bytes())?;
    for uid in cert.userids() {
        let ca_certifications = pgp::valid_certifications_by(&uid, &cert, ca_new_cert.clone());
        assert_eq!(ca_certifications.len(), 1);
    }

    // assert that bob's userid is NOT certified by the new CA
    let cert = pgp::to_cert(certs[1].pub_cert.as_bytes())?;
    for uid in cert.userids() {
        let ca_certifications = pgp::valid_certifications_by(&uid, &cert, ca_new_cert.clone());
        assert_eq!(ca_certifications.len(), 0);
    }

    Ok(())
}
