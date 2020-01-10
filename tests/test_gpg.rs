use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

use openpgp_ca_lib::ca;

mod gnupg;

#[test]
fn run_gpg() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new("example.org").is_ok());

    // get Cert for CA
    let ca_cert = ca.get_ca_cert();
    assert!(ca_cert.is_ok());

    // import CA key into GnuPG
    let mut buf = Vec::new();
    let cert = ca_cert.unwrap();
    cert.as_tsk().serialize(&mut buf).unwrap();
    gnupg::import(&ctx, &buf);

    // FIXME - what to assert?
    assert!(true);
}

#[test]
fn test_alice_authenticates_bob() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // ---- use OpenPGP CA to make a set of keys ----

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    let res = ca.ca_new("example.org");
    assert!(res.is_ok());

    // make CA users
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    let res = ca.user_new(Some(&"Bob"), &["bob@example.org"]);
    assert!(res.is_ok());

    // ---- import keys from OpenPGP CA into GnuPG ----

    // get Cert for CA
    let ca_cert = ca.get_ca_cert();
    assert!(ca_cert.is_ok());

    // import CA key into GnuPG
    let mut buf = Vec::new();
    ca_cert.unwrap().as_tsk().serialize(&mut buf).unwrap();
    gnupg::import(&ctx, &buf);


    // import CA users into GnuPG
    let usercerts = ca.get_all_usercerts();

    assert!(usercerts.is_ok());
    assert_eq!(usercerts.as_ref().ok().unwrap().len(), 2);

    for cert in usercerts.unwrap() {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // ---- set "ultimate" ownertrust for alice ----
    let res = gnupg::edit_trust(&ctx, "alice", 5);

    assert!(res.is_ok());

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx).unwrap();

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(gpg_trust.get("Alice <alice@example.org>"),
               Some(&"u".to_string()));
    assert_eq!(gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
               Some(&"f".to_string()));
    assert_eq!(gpg_trust.get("Bob <bob@example.org>"),
               Some(&"f".to_string()));

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();
}


#[test]
/// Alice and Bob create their own keys locally,
/// then those keys get imported into the CA.
/// TSigning the CA key is done in user GnuPG contexts,
/// signing of user keys in the CA.
/// Alice imports Bob's key from CA and checks if she can authenticate Bob.
fn test_alice_authenticates_bob_key_imports() {
    let ctx_alice = make_context!();
    let ctx_bob = make_context!();

    let home_path_alice = String::from(ctx_alice.get_homedir().to_str().unwrap());
    let home_path_bob = String::from(ctx_bob.get_homedir().to_str().unwrap());


    let ctx_ca = make_context!();

    let home_path_ca = String::from(ctx_ca.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path_ca);

    // ---- init OpenPGP CA key ----
    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    let res = ca.ca_new("example.org");
    assert!(res.is_ok());

    let ca_key = ca.export_pubkey().unwrap();

    // ---- import CA key from OpenPGP CA into GnuPG instances ----
    gnupg::import(&ctx_alice, ca_key.as_bytes());
    gnupg::import(&ctx_bob, ca_key.as_bytes());

    // get Cert for CA
    let ca_cert = ca.get_ca_cert();
    assert!(ca_cert.is_ok());
    let ca_cert = ca_cert.unwrap();

    let ca_keyid = ca_cert.clone().keyid().to_hex();

    // create users in their respective GnuPG contexts
    gnupg::create_user(&ctx_alice, "Alice <alice@example.org>");
    gnupg::create_user(&ctx_bob, "Bob <bob@example.org>");


    // create tsig for ca key in user GnuPG contexts
    gnupg::tsign(&ctx_alice, &ca_keyid, 1, 2)
        .expect("tsign alice failed");
    gnupg::tsign(&ctx_bob, &ca_keyid, 1, 2)
        .expect("tsign bob failed");


    // export CA key from both contexts, import to CA
    let alice_ca_key = gnupg::export(&ctx_alice, &"openpgp-ca@example.org");
    let bob_ca_key = gnupg::export(&ctx_bob, &"openpgp-ca@example.org");

    let alice_ca_file = format!("{}/ca.key.alice", home_path_alice);
    let bob_ca_file = format!("{}/ca.key.bob", home_path_bob);

    std::fs::write(&alice_ca_file, alice_ca_key).expect("Unable to write file");
    std::fs::write(&bob_ca_file, bob_ca_key).expect("Unable to write file");

    ca.import_tsig(&alice_ca_file)
        .expect("import CA tsig from Alice failed");
    ca.import_tsig(&bob_ca_file)
        .expect("import CA tsig from Bob failed");


    // export alice + bob from their contexts
    let alice_file = format!("{}/alice.key", home_path_alice);

    let alice_key = gnupg::export(&ctx_alice, &"alice@example.org");
    std::fs::write(&alice_file, alice_key).expect("Unable to write file");

    // - bob
    let bob_file = format!("{}/bob.key", home_path_bob);

    let bob_key = gnupg::export(&ctx_bob, &"bob@example.org");
    std::fs::write(&bob_file, bob_key).expect("Unable to write file");


    // import alice + bob keys into CA
    ca.user_import(Some("Alice"), &vec!["alice@example.org"],
                   &alice_file, None, None, false)
        .expect("import Alice to CA failed");

    ca.user_import(Some("Bob"), &vec!["bob@example.org"],
                   &bob_file, None, None, false)
        .expect("import Bob to CA failed");


    // export bob, CA-key from CA
    let ca_key = ca.export_pubkey().unwrap();
    let usercerts = ca.get_usercerts(&"bob@example.org").unwrap();
    let bob = usercerts.first().unwrap();

    // import bob+CA key into alice's GnuPG context
    gnupg::import(&ctx_alice, ca_key.as_bytes());
    gnupg::import(&ctx_alice, bob.pub_cert.as_bytes());

    // ---- set "ultimate" ownertrust for alice ----
    let res = gnupg::edit_trust(&ctx_alice, "alice", 5);

    assert!(res.is_ok());

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx_alice).unwrap();

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(gpg_trust.get("Alice <alice@example.org>"),
               Some(&"u".to_string()));
    assert_eq!(gpg_trust.get("OpenPGP CA <openpgp-ca@example.org>"),
               Some(&"f".to_string()));
    assert_eq!(gpg_trust.get("Bob <bob@example.org>"),
               Some(&"f".to_string()));
}

#[test]
fn test_bridge() {
    let ctx = make_context!();

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());

    let db1 = format!("{}/ca1.sqlite", home_path);
    let db2 = format!("{}/ca2.sqlite", home_path);

    let mut ca1 = ca::Ca::new(Some(&db1));
    let mut ca2 = ca::Ca::new(Some(&db2));

    // ---- populate first OpenPGP CA instance ----

    // make new CA key
    let res = ca1.ca_new("some.org");
    assert!(res.is_ok());

    // make CA user
    let res = ca1.user_new(Some(&"Alice"), &["alice@some.org"]);
    assert!(res.is_ok());

    // ---- populate second OpenPGP CA instance ----

    // make new CA key
    let res = ca2.ca_new("other.org");
    assert!(res.is_ok());

    // make CA user
    let res = ca2.user_new(Some(&"Bob"), &["bob@other.org"]);
    assert!(res.is_ok());

    // make CA user that is out of the domain scope for ca2
    let res = ca2.user_new(Some(&"Carol"), &["carol@third.org"]);
    assert!(res.is_ok());

    // ---- setup bridges: scoped trust between one.org and two.org ---

    let ca_some_file = format!("{}/ca1.pubkey", home_path);
    let ca_other_file = format!("{}/ca2.pubkey", home_path);

    let pub_ca1 = ca1.export_pubkey().unwrap();
    let pub_ca2 = ca2.export_pubkey().unwrap();

    std::fs::write(&ca_some_file, pub_ca1).expect("Unable to write file");
    std::fs::write(&ca_other_file, pub_ca2).expect("Unable to write file");

    ca1.bridge_new(&ca_other_file, None, None);
    ca2.bridge_new(&ca_some_file, None, None);

    // ---- import all keys from OpenPGP CA into one GnuPG instance ----

    // get Cert for ca1 from ca2 bridge
    // (this has the signed version of the ca1 pubkey)

    let bridges2 = ca2.get_bridges();
    assert!(bridges2.is_ok());

    let bridges2 = bridges2.unwrap();
    assert_eq!(bridges2.len(), 1);

    let ca1_cert = &bridges2[0].pub_key;


    // get Cert for ca2 from ca1 bridge
    // (this has the signed version of the ca2 pubkey)
    let bridges1 = ca1.get_bridges();
    assert!(bridges1.is_ok());

    let bridges1 = bridges1.unwrap();
    assert_eq!(bridges1.len(), 1);

    let ca2_cert = &bridges1[0].pub_key;


    // import CA keys into GnuPG
    gnupg::import(&ctx, ca1_cert.as_bytes());
    gnupg::import(&ctx, ca2_cert.as_bytes());

    // import CA1 users into GnuPG
    let usercerts1 = ca1.get_all_usercerts();

    assert!(usercerts1.is_ok());
    assert_eq!(usercerts1.as_ref().ok().unwrap().len(), 1);

    for cert in usercerts1.unwrap() {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }

    // import CA2 users into GnuPG
    let usercerts2 = ca2.get_all_usercerts();

    assert!(usercerts2.is_ok());
    assert_eq!(usercerts2.as_ref().ok().unwrap().len(), 2);

    for cert in usercerts2.unwrap() {
        gnupg::import(&ctx, cert.pub_cert.as_bytes());
    }


    // ---- set "ultimate" ownertrust for alice ----
    let res = gnupg::edit_trust(&ctx, "alice", 5);

    assert!(res.is_ok());

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx).unwrap();

    assert_eq!(gpg_trust.len(), 5);

    assert_eq!(gpg_trust.get("Alice <alice@some.org>"),
               Some(&"u".to_string()),
               "alice@some.org");
    assert_eq!(gpg_trust.get("OpenPGP CA <openpgp-ca@some.org>"),
               Some(&"f".to_string()),
               "openpgp-ca@some.org");
    assert_eq!(gpg_trust.get("OpenPGP CA <openpgp-ca@other.org>"),
               Some(&"f".to_string()),
               "openpgp-ca@other.org");
    assert_eq!(gpg_trust.get("Bob <bob@other.org>"),
               Some(&"f".to_string()),
               "bob@other.org");
    assert_eq!(gpg_trust.get("Carol <carol@third.org>"),
               Some(&"-".to_string()),
               "carol@third.org");
}