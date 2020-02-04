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

use openpgp_ca_lib::ca;

use failure::{self, Fallible, ResultExt};
use std::path::PathBuf;

pub mod gnupg;

#[test]
fn test_alice_authenticates_bob_centralized() -> Fallible<()> {
    let ctx = gnupg::make_context()?;

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // ---- use OpenPGP CA to make a set of keys ----

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", None)?;

    // make CA users
    ca.usercert_new(Some(&"Alice"), &["alice@example.org"])?;
    ca.usercert_new(Some(&"Bob"), &["bob@example.org"])?;

    // ---- import keys from OpenPGP CA into GnuPG ----

    // get Cert for CA
    let ca_cert = ca.get_ca_cert()?;

    // import CA key into GnuPG
    let mut buf = Vec::new();
    ca_cert.as_tsk().serialize(&mut buf)?;
    gnupg::import(&ctx, &buf);

    // import CA users into GnuPG
    let usercerts = ca.get_all_usercerts()?;

    assert_eq!(usercerts.len(), 2);

    for cert in usercerts {
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
/// Alice and Bob create their own keys locally,
/// then those keys get imported into the CA.
///
/// TSigning the CA key is done in user GnuPG contexts,
/// signing of user keys in the CA.
/// Alice imports Bob's key from CA and checks if she can authenticate Bob.
fn test_alice_authenticates_bob_decentralized() -> Fallible<()> {
    let ctx_alice = gnupg::make_context()?;
    let ctx_bob = gnupg::make_context()?;

    let ctx_ca = gnupg::make_context()?;

    let home_path_ca = String::from(ctx_ca.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path_ca);

    // ---- init OpenPGP CA key ----
    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    ca.ca_new("example.org", None)?;

    let ca_key = ca.get_ca_pubkey_armored()?;

    // ---- import CA key from OpenPGP CA into GnuPG instances ----
    gnupg::import(&ctx_alice, ca_key.as_bytes());
    gnupg::import(&ctx_bob, ca_key.as_bytes());

    // get Cert for CA
    let ca_cert = ca.get_ca_cert()?;

    let ca_keyid = ca_cert.keyid().to_hex();

    // create users in their respective GnuPG contexts
    gnupg::create_user(&ctx_alice, "Alice <alice@example.org>");
    gnupg::create_user(&ctx_bob, "Bob <bob@example.org>");

    // create tsig for ca key in user GnuPG contexts
    gnupg::tsign(&ctx_alice, &ca_keyid, 1, 2).expect("tsign alice failed");
    gnupg::tsign(&ctx_bob, &ca_keyid, 1, 2).expect("tsign bob failed");

    // export CA key from both contexts, import to CA
    let alice_ca_key = gnupg::export(&ctx_alice, &"openpgp-ca@example.org");
    let bob_ca_key = gnupg::export(&ctx_bob, &"openpgp-ca@example.org");

    ca.import_tsig_for_ca(&alice_ca_key)
        .context("import CA tsig from Alice failed")?;
    ca.import_tsig_for_ca(&bob_ca_key)
        .context("import CA tsig from Bob failed")?;

    // get public keys for alice and bob from their gnupg contexts
    let alice_key = gnupg::export(&ctx_alice, &"alice@example.org");
    let bob_key = gnupg::export(&ctx_bob, &"bob@example.org");

    // import public keys for alice and bob into CA
    ca.usercert_import(
        &alice_key,
        None,
        Some("Alice"),
        &["alice@example.org"],
    )
    .context("import Alice to CA failed")?;

    ca.usercert_import(&bob_key, None, Some("Bob"), &["bob@example.org"])
        .context("import Bob to CA failed")?;

    // export bob, CA-key from CA
    let ca_key = ca.get_ca_pubkey_armored()?;
    let usercerts = ca.get_usercerts(&"bob@example.org")?;
    let bob = usercerts.first().unwrap();

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
fn test_bridge() -> Fallible<()> {
    let ctx = gnupg::make_context()?;

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());

    let db1 = format!("{}/ca1.sqlite", home_path);
    let db2 = format!("{}/ca2.sqlite", home_path);

    let mut ca1 = ca::Ca::new(Some(&db1));
    let mut ca2 = ca::Ca::new(Some(&db2));

    // ---- populate first OpenPGP CA instance ----

    // make new CA key
    ca1.ca_new("some.org", None)?;

    // make CA user
    assert!(ca1
        .usercert_new(Some(&"Alice"), &["alice@some.org"])
        .is_ok());

    // ---- populate second OpenPGP CA instance ----

    // make new CA key
    ca2.ca_new("other.org", None)?;

    // make CA user
    ca2.usercert_new(Some(&"Bob"), &["bob@other.org"])?;

    // make CA user that is out of the domain scope for ca2
    ca2.usercert_new(Some(&"Carol"), &["carol@third.org"])?;

    // ---- setup bridges: scoped trust between one.org and two.org ---

    let ca_some_file = format!("{}/ca1.pubkey", home_path);
    let ca_other_file = format!("{}/ca2.pubkey", home_path);

    let pub_ca1 = ca1.get_ca_pubkey_armored()?;
    let pub_ca2 = ca2.get_ca_pubkey_armored()?;

    std::fs::write(&ca_some_file, pub_ca1).expect("Unable to write file");
    std::fs::write(&ca_other_file, pub_ca2).expect("Unable to write file");

    ca1.bridge_new(&PathBuf::from(ca_other_file), None, None)?;
    ca2.bridge_new(&PathBuf::from(ca_some_file), None, None)?;

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1 from ca2 bridge
    // (this has the signed version of the ca1 pubkey)

    let bridges2 = ca2.get_bridges()?;
    assert_eq!(bridges2.len(), 1);

    let ca1_cert = &bridges2[0].pub_key;

    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.get_bridges()?;
    assert_eq!(bridges1.len(), 1);

    let ca2_cert = &bridges1[0].pub_key;

    // import CA keys into GnuPG
    gnupg::import(&ctx, ca1_cert.as_bytes());
    gnupg::import(&ctx, ca2_cert.as_bytes());

    // import CA1 users into GnuPG
    let usercerts1 = ca1.get_all_usercerts()?;

    assert_eq!(usercerts1.len(), 1);

    for cert in usercerts1 {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // import CA2 users into GnuPG
    let usercerts2 = ca2.get_all_usercerts()?;

    assert_eq!(usercerts2.len(), 2);

    for cert in usercerts2 {
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
