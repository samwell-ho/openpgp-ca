// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
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

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio_core::reactor::Core;

use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::Builder;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::{Cert, Fingerprint, KeyID};
use sequoia_openpgp as openpgp;

use openpgp_ca_lib::ca::OpenpgpCa;

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
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 1);

    let usercert = &usercerts[0];
    let emails = ca.emails_get(usercert)?;

    assert_eq!(emails.len(), 1);

    let revocs = ca.revocations_get(usercert)?;
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
/// This test also exercises the OpenpgpCa::usercerts_expired() function.
fn test_update_usercert_key() -> Result<()> {
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

    ca.usercert_import_new(
        &alice1_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // check the state of CA data
    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // check that expiry is ~2y
    let cert = OpenpgpCa::usercert_to_cert(alice)?;

    cert.alive(&policy, in_one_year)?;
    assert!(cert.alive(&policy, in_three_years).is_err());

    // check the same with ca.usercert_expiry()
    let exp1 = ca.usercerts_expired(365)?;
    assert_eq!(exp1.len(), 1);
    let (_, (alive, _)) = exp1.iter().next().unwrap();
    assert!(alive);

    let exp3 = ca.usercerts_expired(3 * 365).unwrap();
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(!alive);

    // edit key with gpg, then import new version into CA
    gnupg::edit_expire(&ctx, "alice@example.org", "5y")?;
    let alice2_key = gnupg::export(&ctx, &"alice@example.org");

    // get usercert for alice
    let usercerts = ca.usercerts_get("alice@example.org")?;
    assert_eq!(usercerts.len(), 1);
    let alice = &usercerts[0];

    // store updated version of cert
    ca.usercert_import_update(&alice2_key, alice)?;

    // check the state of CA data
    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = OpenpgpCa::usercert_to_cert(&usercerts[0])?;

    assert!(cert.alive(&policy, in_three_years).is_ok());
    assert!(!cert.alive(&policy, in_six_years).is_ok());

    // check the same with ca.usercert_expiry()
    let exp3 = ca.usercerts_expired(3 * 365)?;
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(alive);

    let exp6 = ca.usercerts_expired(6 * 365)?;
    assert_eq!(exp6.len(), 1);
    let (_, (alive, _)) = exp6.iter().next().unwrap();
    assert!(!alive);

    Ok(())
}

#[test]
/// Create a CA, then externally create a user cert and import it.
/// Externally create a new user cert for the same email, then import that
/// cert as an update for the OpenPGP CA usercert.
///
/// Expected outcome: Two usercerts exist in OpenPGP CA, the newer one
/// points to the older one with the "updates_cert_id" field.
fn test_update_user_cert() -> Result<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // import key as new user
    let ctx_alice1 = gnupg::make_context()?;
    gnupg::create_user(&ctx_alice1, "alice@example.org");
    let alice1_key = gnupg::export(&ctx_alice1, &"alice@example.org");

    ca.usercert_import_new(
        &alice1_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // import key as update to user key
    let ctx_alice2 = gnupg::make_context()?;
    gnupg::create_user(&ctx_alice2, "alice@example.org");
    let alice2_key = gnupg::export(&ctx_alice2, &"alice@example.org");

    // get usercert for alice
    let usercerts = ca.usercerts_get("alice@example.org")?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // store updated version of cert
    ca.usercert_import_update(&alice2_key, alice)?;

    // check the state of CA data
    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 2);

    // test that the "new" usercert points to the "old" usercert via
    // the updates_cert_id database field
    for uc in usercerts {
        match uc.id {
            1 => assert_eq!(uc.updates_cert_id, None),
            2 => assert_eq!(uc.updates_cert_id, Some(1)),
            _ => panic!("only ID 1 and 2 should exist"),
        }
    }

    // FIXME: add method to filter for "current" usercerts, or similar?!

    Ok(())
}

#[test]
/// Create a new CA and two usercerts with the same email.
///
/// Expected outcome: two independent usercerts got created.
fn test_ca_insert_duplicate_email() -> Result<()> {
    // two usercerts with the same email are considered distinct certs
    // (e.g. "normal cert" vs "code signing cert")

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    assert!(ca.ca_init("example.org", None).is_ok());

    // make CA user
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;

    // make another CA user with the same email address
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 2);

    // ca cert should be tsigned by all usercerts.
    for uc in &usercerts {
        let tsig = ca.usercert_check_tsig_on_ca(&uc)?;
        assert!(tsig);

        // "updates_cert_id" should be None for all usercerts.
        assert_eq!(uc.updates_cert_id, None);
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
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;
    ca.usercert_new(
        Some(&"Bob"),
        &["bob@example.org", "bob@other.org"],
        false,
    )?;
    ca.usercert_new(Some(&"Carol"), &["carol@other.org"], false)?;

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

    let j = Fingerprint::from_hex("CBCD8F030588653EEDD7E2659B7DD433F254904A")?;
    let justus: Cert = core.run(hagrid.get(&KeyID::from(j)))?;
    let justus_key = OpenpgpCa::cert_to_armored(&justus)?;

    let n = Fingerprint::from_hex("8F17777118A33DDA9BA48E62AACB3243630052D9")?;
    let neal: Cert = core.run(hagrid.get(&KeyID::from(n)))?;
    let neal_key = OpenpgpCa::cert_to_armored(&neal)?;

    // -- import keys into CA

    let db = format!("{}/ca.sqlite", home_path);

    let ca = OpenpgpCa::new(Some(&db))?;

    ca.ca_init("sequoia-pgp.org", None)?;

    ca.usercert_import_new(
        &justus_key,
        None,
        None,
        &["justus@sequoia-pgp.org"],
    )?;
    ca.usercert_import_new(&neal_key, None, None, &["neal@sequoia-pgp.org"])?;

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
/// Check that CA API shows one usercert with two revocations.
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

    ca.usercert_import_new(&alice_key, None, None, &[])?;

    // make two different revocation certificates and import them into the CA
    let revoc_file1 = format!("{}/alice.revoc1", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file1, 1)?;

    let revoc_file3 = format!("{}/alice.revoc3", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file3, 3)?;

    ca.revocation_add(&PathBuf::from(revoc_file1))?;
    ca.revocation_add(&PathBuf::from(revoc_file3))?;

    // check data in CA
    let usercerts = ca.usercerts_get_all()?;

    // check that name/email has been autodetected on CA import from the pubkey
    assert_eq!(usercerts.len(), 1);
    let alice = &usercerts[0];

    assert_eq!(alice.name, Some("Alice".to_string()));

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
/// Check the output of OpenpgpCa::usercerts_check_signatures().
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

    ca.usercert_import_new(
        &alice_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice to CA failed")?;

    // create/import bob
    gnupg::create_user(&ctx, "bob@example.org");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");

    // CA does not signs bob's key because the "email" parameter is empty.
    // Only userids that are supplied in `email` are signed by the CA.
    ca.usercert_import_new(&bob_key, None, Some("Bob"), &[])
        .context("import Bob to CA failed")?;

    // create carol, CA will sign carol's key.
    // also, CA key gets a tsig by carol
    ca.usercert_new(Some(&"Carol"), &["carol@example.org"], false)?;

    let sigs = ca.usercerts_check_signatures()?;
    for (usercert, (sig_from_ca, tsig_on_ca)) in sigs {
        match usercert.name.as_deref() {
            Some("Alice") => {
                assert!(sig_from_ca);
                assert!(!tsig_on_ca);
            }
            Some("Bob") => {
                assert!(!sig_from_ca);
                assert!(!tsig_on_ca);
            }
            Some("Carol") => {
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
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;

    let usercerts = ca.usercerts_get_all()?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

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
    ca.usercert_import_new(
        &alice_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )?;

    // get alice cert back from CA
    let users = ca.usercerts_get("alice@example.org")?;
    assert_eq!(users.len(), 1);

    let alice = &users[0];
    let cert = OpenpgpCa::usercert_to_cert(&alice)?;

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

    // check signature status via OpenpgpCa::usercerts_check_signatures()
    let sigs = ca.usercerts_check_signatures()?;
    assert_eq!(sigs.len(), 1);
    for (usercert, (sig_from_ca, tsig_on_ca)) in sigs {
        match usercert.name.as_deref() {
            Some("Alice") => {
                assert!(sig_from_ca);
                assert!(!tsig_on_ca);
            }
            _ => panic!(),
        }
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
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"], false)?;

    // gpg: make key for Bob
    gnupg::create_user(&ctx, "Bob <bob@example.org>");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");
    ca.usercert_import_new(&bob_key, None, None, &[])?;

    // make a revocation certificate for bob ...
    let revoc_file = format!("{}/bob.revoc", home_path);
    gnupg::make_revocation(&ctx, "bob@example.org", &revoc_file, 1)?;

    // ... remove the issuer fingerprint ...
    let p = openpgp::Packet::from_file(&revoc_file)
        .context("Input could not be parsed")?;

    let armored = if let openpgp::Packet::Signature(s) = p {
        // modify Signature: remove IssuerFingerprint subpacket

        println!("signature: {:#?}", &s);

        let mut b: Builder = s.into();

        b.remove_all(SubpacketTag::IssuerFingerprint);

        // use Bob as a Signer
        let bob_sec = gnupg::export_secret(&ctx, &"bob@example.org");
        let bob_cert = Cert::from_bytes(&bob_sec)?;
        let mut keypair = bob_cert
            .primary_key()
            .key()
            .clone()
            .mark_parts_secret()?
            .into_keypair()?;

        let sig = b.sign_direct_key(&mut keypair)?;

        OpenpgpCa::sig_to_armored(&sig)
            .context("couldn't armor revocation cert")?
    } else {
        panic!("Error handling Signature Packet");
    };

    println!("revocation: {}", &armored);

    // save in file
    std::fs::write(&revoc_file, &armored)?;

    // ... and import into the CA
    ca.revocation_add(&PathBuf::from(&revoc_file))?;

    //
    // -- check data in CA --
    let usercerts = ca.usercerts_get_all()?;

    let alice = usercerts
        .iter()
        .find(|u| u.name == Some("Alice".to_owned()))
        .unwrap();
    let alice_revs = ca.revocations_get(alice)?;
    assert_eq!(alice_revs.len(), 1, "Revocation generated by OpenPGP CA");

    let bob = usercerts
        .iter()
        .find(|u| u.name == Some("Bob".to_owned()))
        .unwrap();
    let bob_revs = ca.revocations_get(bob)?;
    assert_eq!(bob_revs.len(), 1, "Revocation without issuer fingerprint");

    Ok(())
}
