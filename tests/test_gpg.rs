use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use openpgp_ca_lib::ca;

mod gnupg;

#[test]
fn run_gpg() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());

    // get Cert for CA
    let ca_cert = ca.get_ca_key();
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
fn test_alice_trusts_bob() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // ---- use OpenPGP CA to make a set of keys ----

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    let res = ca.ca_new(&["ca@example.org"]);
    assert!(res.is_ok());

    // make CA users
    let res = ca.user_new(Some(&"Alice"), Some(&["alice@example.org"]));
    assert!(res.is_ok());

    let res = ca.user_new(Some(&"Bob"), Some(&["bob@example.org"]));
    assert!(res.is_ok());

    // ---- import keys from OpenPGP CA into GnuPG ----

    // get Cert for CA
    let ca_cert = ca.get_ca_key();
    assert!(ca_cert.is_ok());

    // import CA key into GnuPG
    let mut buf = Vec::new();
    ca_cert.unwrap().as_tsk().serialize(&mut buf).unwrap();
    gnupg::import(&ctx, &buf);


    // import CA users into GnuPG
    let users = ca.get_users();

    assert!(users.is_ok());
    assert_eq!(users.as_ref().ok().unwrap().len(), 2);

    users.unwrap().iter()
        .for_each(|u| gnupg::import(&ctx, u.pub_key.as_bytes()));


    // ---- set "ultimate" ownertrust for alice ----
    let res = gnupg::edit_trust(&ctx, "alice", 5);

    assert!(res.is_ok());

    // ---- read calculated "trust" per uid from GnuPG ----
    let gpg_trust = gnupg::list_keys(&ctx).unwrap();

    assert_eq!(gpg_trust.len(), 3);

    assert_eq!(gpg_trust.get("alice@example.org"), Some(&"u".to_string()));
    assert_eq!(gpg_trust.get("ca@example.org"), Some(&"f".to_string()));
    assert_eq!(gpg_trust.get("bob@example.org"), Some(&"f".to_string()));

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();
}