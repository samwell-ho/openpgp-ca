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

use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use openpgp_ca_lib::ca::OpenpgpCa;

use anyhow::{Context, Result};
use std::path::PathBuf;

pub mod gnupg;

#[test]
/// Create a new CA. Create user certs for Alice and Bob in OpenPGP CA.
///
/// Export all keys to a gnupg instance, set ownertrust for Alice to
/// "ultimate".
///
/// Check that gnupg considers Bob and the CA admin as "full"ly trusted.
fn test_alice_authenticates_bob_centralized() -> Result<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // ---- use OpenPGP CA to make a set of keys ----

    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    // make CA users
    ca.user_new(Some(&"Alice"), &["alice@example.org"], false)?;
    ca.user_new(Some(&"Bob"), &["bob@example.org"], false)?;

    // ---- import keys from OpenPGP CA into GnuPG ----

    // get Cert for CA
    let ca_cert = ca.ca_get_cert()?;

    // import CA key into GnuPG
    let mut buf = Vec::new();
    ca_cert.as_tsk().serialize(&mut buf)?;
    gnupg::import(&ctx, &buf);

    // import CA users into GnuPG
    let certs = ca.certs_get_all()?;

    assert_eq!(certs.len(), 2);

    for cert in certs {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // ---- set "ultimate" ownertrust for alice ----
    gnupg::edit_trust(&ctx, "alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx)?;

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(
        gpg_trust.get("Alice <alice@example.org>"),
        Some(&"u".to_string())
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
        Some(&"f".to_string())
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@example.org>"),
        Some(&"f".to_string())
    );

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();

    Ok(())
}

#[test]
/// A new CA instance is created. The CA Admin's public key is exported (for
/// Alice and Bob).
///
/// Alice and Bob create their own keys locally in two seperate gnupg
/// instances, and tsign the CA Admin Key, respectively.
///
/// Their keys plus the signatures on the CA Admin key get imported into the
/// CA.
///
/// Export Bob and the CA Admin's key from OpenPGP CA and import into
/// Alice's gnupg instance.
///
/// Expect gnupg in Alice's instance to consider both the CA Admin key and
/// Bob and "full"ly trusted.
fn test_alice_authenticates_bob_decentralized() -> Result<()> {
    let ctx_alice = gnupg::make_context()?;
    let ctx_bob = gnupg::make_context()?;

    let ctx_ca = gnupg::make_context()?;

    let home_path_ca = String::from(ctx_ca.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path_ca);

    // ---- init OpenPGP CA key ----
    let ca = OpenpgpCa::new(Some(&db))?;

    // make new CA key
    ca.ca_init("example.org", None)?;

    let ca_key = ca.ca_get_pubkey_armored()?;

    // ---- import CA key from OpenPGP CA into GnuPG instances ----
    gnupg::import(&ctx_alice, ca_key.as_bytes());
    gnupg::import(&ctx_bob, ca_key.as_bytes());

    // get Cert for CA
    let ca_cert = ca.ca_get_cert()?;

    let ca_keyid = format!("{:X}", ca_cert.keyid());

    // create users in their respective GnuPG contexts
    gnupg::create_user(&ctx_alice, "Alice <alice@example.org>");
    gnupg::create_user(&ctx_bob, "Bob <bob@example.org>");

    // create tsig for ca key in user GnuPG contexts
    gnupg::tsign(&ctx_alice, &ca_keyid, 1, 2).expect("tsign alice failed");
    gnupg::tsign(&ctx_bob, &ca_keyid, 1, 2).expect("tsign bob failed");

    // export CA key from both contexts, import to CA
    let alice_ca_key = gnupg::export(&ctx_alice, &"openpgp-ca@example.org");
    let bob_ca_key = gnupg::export(&ctx_bob, &"openpgp-ca@example.org");

    ca.ca_import_tsig(&alice_ca_key)
        .context("import CA tsig from Alice failed")?;
    ca.ca_import_tsig(&bob_ca_key)
        .context("import CA tsig from Bob failed")?;

    // get public keys for alice and bob from their gnupg contexts
    let alice_key = gnupg::export(&ctx_alice, &"alice@example.org");
    let bob_key = gnupg::export(&ctx_bob, &"bob@example.org");

    // import public keys for alice and bob into CA
    ca.cert_import_new(
        &alice_key,
        vec![],
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice to CA failed")?;

    ca.cert_import_new(&bob_key, vec![], Some("Bob"), &["bob@example.org"])
        .context("import Bob to CA failed")?;

    // export bob, CA-key from CA
    let ca_key = ca.ca_get_pubkey_armored()?;
    let certs = ca.certs_get(&"bob@example.org")?;
    let bob = certs.first().unwrap();

    // import bob+CA key into alice's GnuPG context
    gnupg::import(&ctx_alice, ca_key.as_bytes());
    gnupg::import(&ctx_alice, bob.pub_cert.as_bytes());

    // ---- set "ultimate" ownertrust for alice ----
    gnupg::edit_trust(&ctx_alice, "alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx_alice)?;

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(
        gpg_trust.get("Alice <alice@example.org>"),
        Some(&"u".to_string())
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
        Some(&"f".to_string())
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@example.org>"),
        Some(&"f".to_string())
    );

    Ok(())
}

#[test]
/// Set up two OpenPGP CA instances for the domains "some.org" and "other.org"
///
/// Create users in each CA, set up a bridge between the two OpenPGP CA
/// instances.
///
/// Export all keys from both CA instances and import them into
/// one gnupg instance. Set ownertrust on one of the users to "ultimate".
///
/// Check that trust of all other keys is "full".
///
/// Except for the user Carol whose userid is in an external domain.
/// Users of CA2 trust Carol, because CA2 signed Carol's key.
/// However, users of CA1 will not, because their trust of keys that CA2
/// signed is scoped to the main domain of CA2's organization.
fn test_bridge() -> Result<()> {
    let ctx = gnupg::make_context()?;

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());

    let db1 = format!("{}/ca1.sqlite", home_path);
    let db2 = format!("{}/ca2.sqlite", home_path);

    let ca1 = OpenpgpCa::new(Some(&db1))?;
    let ca2 = OpenpgpCa::new(Some(&db2))?;

    // ---- populate first OpenPGP CA instance ----

    // make new CA key
    ca1.ca_init("some.org", None)?;

    // make CA user
    assert!(ca1
        .user_new(Some(&"Alice"), &["alice@some.org"], false)
        .is_ok());

    // ---- populate second OpenPGP CA instance ----

    // make new CA key
    ca2.ca_init("other.org", None)?;

    // make CA user
    ca2.user_new(Some(&"Bob"), &["bob@other.org"], false)?;

    // make CA user that is out of the domain scope for ca2
    ca2.user_new(Some(&"Carol"), &["carol@third.org"], false)?;

    // ---- setup bridges: scoped trust between one.org and two.org ---

    let ca_some_file = format!("{}/ca1.pubkey", home_path);
    let ca_other_file = format!("{}/ca2.pubkey", home_path);

    let pub_ca1 = ca1.ca_get_pubkey_armored()?;
    let pub_ca2 = ca2.ca_get_pubkey_armored()?;

    std::fs::write(&ca_some_file, pub_ca1).expect("Unable to write file");
    std::fs::write(&ca_other_file, pub_ca2).expect("Unable to write file");

    ca1.bridge_new(&PathBuf::from(ca_other_file), None, None)?;
    ca2.bridge_new(&PathBuf::from(ca_some_file), None, None)?;

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1 from ca2 bridge
    // (this has the signed version of the ca1 pubkey)

    let bridges2 = ca2.bridges_get()?;
    assert_eq!(bridges2.len(), 1);

    let ca1_cert = &bridges2[0].pub_key;

    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.bridges_get()?;
    assert_eq!(bridges1.len(), 1);

    let ca2_cert = &bridges1[0].pub_key;

    // import CA keys into GnuPG
    gnupg::import(&ctx, ca1_cert.as_bytes());
    gnupg::import(&ctx, ca2_cert.as_bytes());

    // import CA1 users into GnuPG
    let certs1 = ca1.certs_get_all()?;

    assert_eq!(certs1.len(), 1);

    for cert in certs1 {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // import CA2 users into GnuPG
    let certs2 = ca2.certs_get_all()?;

    assert_eq!(certs2.len(), 2);

    for cert in certs2 {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // ---- set "ultimate" ownertrust for alice ----
    gnupg::edit_trust(&ctx, "alice", 5)?;

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx)?;

    assert_eq!(gpg_trust.len(), 5);

    assert_eq!(
        gpg_trust.get("Alice <alice@some.org>"),
        Some(&"u".to_string()),
        "alice@some.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@some.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@some.org"
    );
    assert_eq!(
        gpg_trust.get("OpenPGP CA <openpgp-ca@other.org>"),
        Some(&"f".to_string()),
        "openpgp-ca@other.org"
    );
    assert_eq!(
        gpg_trust.get("Bob <bob@other.org>"),
        Some(&"f".to_string()),
        "bob@other.org"
    );
    assert_eq!(
        gpg_trust.get("Carol <carol@third.org>"),
        Some(&"-".to_string()),
        "carol@third.org"
    );

    Ok(())
}
