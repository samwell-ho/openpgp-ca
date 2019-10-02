use std::collections::HashMap;

use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use openpgp_ca_lib::ca;

mod tools;

use tools::Context;
use tools::gpg_edit_trust;
use tools::gpg_import;
use tools::gpg_list_keys;


#[test]
fn run_gpg() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());

    // get TPK for CA
    let ca_tpk = ca.get_ca_key();
    assert!(ca_tpk.is_ok());

    // import CA key into gnupg
    let mut buf = Vec::new();
    let tpk = ca_tpk.unwrap();
    tpk.as_tsk().serialize(&mut buf).unwrap();
    gpg_import(&ctx, &buf);

    assert!(true);
}

#[test]
fn test_alice_trusts_bob() {

    //  gpg --homedir /tmp/.tmphMFRbO/ --list-keys
    //  gpg --homedir /tmp/.tmphMFRbO/ --list-signatures

    //  gpg --homedir /tmp/.tmphMFRbO/ --edit-key alice
    //    -> trust -> 5

    let mut ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // ---- use OpenPGP CA to make keys ----

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    let res = ca.ca_new(&["ca@example.org"]);
    assert!(res.is_ok());

    // make CA users
    let res = ca.user_new(Some(&"Alice"), Some(&["alice@example.org"]));
    assert!(res.is_ok());

    let res = ca.user_new(Some(&"Bob"), Some(&["bob@example.org"]));
    assert!(res.is_ok());

    // ---- import keys into gnupg ----

    // get TPK for CA
    let ca_tpk = ca.get_ca_key();
    assert!(ca_tpk.is_ok());

    // import CA key into gnupg
    let mut buf = Vec::new();
    let tpk = ca_tpk.unwrap();
    tpk.as_tsk().serialize(&mut buf).unwrap();
    gpg_import(&ctx, &buf);


    // get Users
    let users = ca.get_users();

    assert!(users.is_ok());

    for user in users.unwrap() {
        let key = user.pub_key;
        gpg_import(&ctx, key.as_bytes());
    }

    // set "ultimate" ownertrust for alice
    gpg_edit_trust(&ctx, "alice", 5);

    // read key/uid properties from GnuPG
    let res = gpg_list_keys(&ctx).unwrap();

    let uids = res.iter().filter(|&line| line.get(0) == Some("uid"))
        .map(|r| r.clone()).collect::<Vec<_>>();

    assert_eq!(uids.len(), 3);

    let mut gpg_trust = HashMap::new();

    for uid in uids {
        // map: uid -> trust
        gpg_trust.insert(uid.get(9).unwrap().to_owned(),
                         uid.get(1).unwrap().to_owned());
    }

    assert_eq!(gpg_trust.get("alice@example.org"), Some(&"u".to_string()));
    assert_eq!(gpg_trust.get("ca@example.org"), Some(&"f".to_string()));
    assert_eq!(gpg_trust.get("bob@example.org"), Some(&"f".to_string()));

    // don't delete home dir (for manual inspection)
    //    ctx.leak_tempdir();
}
