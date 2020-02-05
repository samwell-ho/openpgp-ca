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

use failure::_core::time::Duration;
use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp;
use sequoia_openpgp::{Cert, Fingerprint, KeyID};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio_core::reactor::Core;

use failure::{self, Fallible, ResultExt};
use sequoia_openpgp::policy::StandardPolicy;

pub mod gnupg;

#[test]
fn test_pgp_wrapper() -> Fallible<()> {
    let (cert, _) =
        pgp::Pgp::make_user_cert(&["foo@example.org"], Some("Foo")).unwrap();

    let armored = pgp::Pgp::priv_cert_to_armored(&cert)?;

    assert!(!armored.is_empty());

    Ok(())
}

#[test]
fn test_ca() -> Fallible<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", Some("Example Org OpenPGP CA Key"))?;

    // make CA user
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;

    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 1);

    let usercert = &usercerts[0];
    let emails = ca.get_emails(usercert)?;

    assert_eq!(emails.len(), 1);

    let revocs = ca.get_revocations(usercert)?;
    assert_eq!(revocs.len(), 1);

    // check that the custom name has ended up in the CA Cert
    let ca_cert = ca.get_ca_cert().unwrap();
    let uid = ca_cert.userids().find(|c| {
        c.binding().userid().name().unwrap()
            == Some("Example Org OpenPGP CA Key".to_owned())
    });

    assert!(uid.is_some());

    Ok(())
}

#[test]
fn test_update_usercert_key() -> Fallible<()> {
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

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", None)?;

    // import key as new user
    gnupg::create_user(&ctx, "alice@example.org");
    let alice1_key = gnupg::export(&ctx, &"alice@example.org");

    ca.usercert_import(
        &alice1_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // check the state of CA data
    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // check that expiry is ~2y
    let cert = pgp::Pgp::armored_to_cert(&alice.pub_cert)?;

    cert.alive(&policy, in_one_year)?;
    assert!(cert.alive(&policy, in_three_years).is_err());

    // check the same with ca.usercert_expiry()
    let exp1 = ca.usercert_expiry(365)?;
    assert_eq!(exp1.len(), 1);
    let (_, (alive, _)) = exp1.iter().next().unwrap();
    assert!(alive);

    let exp3 = ca.usercert_expiry(3 * 365).unwrap();
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(!alive);

    // edit key with gpg, then import new version into CA
    gnupg::edit_expire(&ctx, "alice@example.org", "5y")?;
    let alice2_key = gnupg::export(&ctx, &"alice@example.org");

    // get usercert for alice
    let usercerts = ca.get_usercerts("alice@example.org")?;
    assert_eq!(usercerts.len(), 1);
    let alice = &usercerts[0];

    // store updated version of cert
    ca.usercert_import_update(&alice2_key, alice)?;

    // check the state of CA data
    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = pgp::Pgp::armored_to_cert(&usercerts[0].pub_cert)?;

    assert!(cert.alive(&policy, in_three_years).is_ok());
    assert!(!cert.alive(&policy, in_six_years).is_ok());

    // check the same with ca.usercert_expiry()
    let exp3 = ca.usercert_expiry(3 * 365)?;
    assert_eq!(exp3.len(), 1);
    let (_, (alive, _)) = exp3.iter().next().unwrap();
    assert!(alive);

    let exp5 = ca.usercert_expiry(5 * 365)?;
    assert_eq!(exp5.len(), 1);
    let (_, (alive, _)) = exp5.iter().next().unwrap();
    assert!(!alive);

    Ok(())
}

#[test]
fn test_update_user_cert() -> Fallible<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", None)?;

    // import key as new user
    let ctx_alice1 = gnupg::make_context()?;
    gnupg::create_user(&ctx_alice1, "alice@example.org");
    let alice1_key = gnupg::export(&ctx_alice1, &"alice@example.org");

    ca.usercert_import(
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
    let usercerts = ca.get_usercerts("alice@example.org")?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // store updated version of cert
    ca.usercert_import_update(&alice2_key, alice)?;

    // check the state of CA data
    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 2);

    // FIXME: add method to filter for "current" usercerts, or similar?!

    //    let certs = ca.get_user_certs(&usercerts[0]);
    //    assert!(certs.is_ok());
    //
    //    let certs = certs.unwrap();
    //
    //    // expect to find both user certs
    //    assert_eq!(certs.len(), 2);

    Ok(())
}

#[test]
fn test_ca_insert_duplicate_email() -> Fallible<()> {
    // two usercerts with the same email are considered distinct certs
    // (e.g. "normal cert" vs "code signing cert")

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new("example.org", None).is_ok());

    // make CA user
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;

    // make another CA user with the same email address
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;

    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 2);

    // ca cert should be tsigned by all usercerts
    for uc in &usercerts {
        let tsig = ca.check_ca_has_tsig(&uc)?;
        assert!(tsig);
    }

    Ok(())
}

#[test]
fn test_ca_export_wkd() -> Fallible<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    ca.ca_new("example.org", None)?;
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;
    ca.usercert_new(Some(&"Bob"), &["bob@example.org"])?;

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("example.org", &wkd_path)?;

    // check that both user keys have been written to files
    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/jycbiujnsxs47xrkethgtj69xuunurok",
    );
    assert!(test_path.is_file());

    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/kei1q4tipxxu1yj79k9kfukdhfy631xe",
    );
    assert!(test_path.is_file());

    // check that CA key has been written to file
    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/ermf4k8pujzwtqqxmskb7355sebj5e4t",
    );
    assert!(test_path.is_file());

    Ok(())
}

#[test]
#[ignore]
fn test_ca_export_wkd_sequoia() -> Fallible<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());

    // -- get keys from hagrid

    let c = sequoia_core::Context::new()?;

    let mut hagrid = sequoia_net::KeyServer::keys_openpgp_org(&c)?;

    let mut core = Core::new()?;

    let j = Fingerprint::from_hex("CBCD8F030588653EEDD7E2659B7DD433F254904A")?;
    let justus: Cert = core.run(hagrid.get(&KeyID::from(j)))?;
    let justus_key = pgp::Pgp::cert_to_armored(&justus)?;

    let n = Fingerprint::from_hex("8F17777118A33DDA9BA48E62AACB3243630052D9")?;
    let neal: Cert = core.run(hagrid.get(&KeyID::from(n)))?;
    let neal_key = pgp::Pgp::cert_to_armored(&neal)?;

    // -- import keys into CA

    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    ca.ca_new("sequoia-pgp.org", None)?;

    ca.usercert_import(&justus_key, None, None, &["justus@sequoia-pgp.org"])?;
    ca.usercert_import(&neal_key, None, None, &["neal@sequoia-pgp.org"])?;

    // -- export as WKD

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    ca.export_wkd("sequoia-pgp.org", &wkd_path)?;

    Ok(())
}

#[test]
fn test_ca_multiple_revocations() -> Fallible<()> {
    // create two different revocation certificates for one key and import them

    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", None)?;

    // gpg: make key for Alice
    gnupg::create_user(&ctx, "Alice <alice@example.org>");

    let alice_key = gnupg::export(&ctx, &"alice@example.org");

    ca.usercert_import(&alice_key, None, None, &[])?;

    // make two different revocation certificates and import them into the CA
    let revoc_file1 = format!("{}/alice.revoc1", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file1, 1)?;

    let revoc_file3 = format!("{}/alice.revoc3", home_path);
    gnupg::make_revocation(&ctx, "alice@example.org", &revoc_file3, 3)?;

    ca.add_revocation(&PathBuf::from(revoc_file1))?;
    ca.add_revocation(&PathBuf::from(revoc_file3))?;

    // check data in CA
    let usercerts = ca.get_all_usercerts()?;

    // check that name/email has been autodetected on CA import from the pubkey
    assert_eq!(usercerts.len(), 1);
    let alice = &usercerts[0];

    assert_eq!(alice.name, Some("Alice".to_string()));

    let emails = ca.get_emails(alice)?;
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].addr, "alice@example.org");

    // check for both revocation certs
    let revocs = ca.get_revocations(alice)?;

    assert_eq!(revocs.len(), 2);

    Ok(())
}

#[test]
fn test_ca_signatures() -> Fallible<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));
    ca.ca_new("example.org", None)?;

    // create/import alice, CA signs alice's key
    gnupg::create_user(&ctx, "alice@example.org");
    let alice_key = gnupg::export(&ctx, &"alice@example.org");

    ca.usercert_import(
        &alice_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice 1 to CA failed")?;

    // create/import bob, CA does not signs bob's key
    gnupg::create_user(&ctx, "bob@example.org");
    let bob_key = gnupg::export(&ctx, &"bob@example.org");

    ca.usercert_import(&bob_key, None, Some("Bob"), &[])
        .context("import Alice 1 to CA failed")?;

    // create carol, CA will sign carol's key.
    // also, CA key gets a tsig by carol
    ca.usercert_new(Some(&"Carol"), &["carol@example.org"])?;

    let sigs = ca.usercert_signatures()?;
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
fn test_apply_revocation() -> Fallible<()> {
    let ctx = gnupg::make_context()?;
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));
    ca.ca_new("example.org", None)?;

    // make CA user
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;

    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    let rev = ca.get_revocations(alice)?;
    assert_eq!(rev.len(), 1);

    ca.apply_revocation(rev[0].clone())?;

    let rev = ca.get_revocations(alice)?;
    assert_eq!(rev.len(), 1);
    assert!(rev.get(0).unwrap().published);

    Ok(())
}
