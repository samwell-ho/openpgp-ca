use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp;

mod gnupg;

#[test]
fn test_pgp_wrapper() {
    let (cert, _) =
        pgp::Pgp::make_user(&["foo@example.org"], Some("Foo")).unwrap();

    let armored = pgp::Pgp::priv_cert_to_armored(&cert);

    assert!(armored.is_ok());
    assert!(armored.unwrap().len() > 0);
}

#[test]
fn test_ca() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());


    // make CA user
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    let users = ca.get_all_users();
    let users = users.unwrap();

    assert_eq!(users.len(), 1);

    let user = &users[0];
    let emails = ca.get_emails(user);

    assert!(emails.is_ok());
    let emails = emails.unwrap();
    assert_eq!(emails.len(), 1);

    let certs = ca.get_user_certs(user);
    assert!(certs.is_ok());
    let certs = certs.unwrap();
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let revocs = ca.get_revocations(cert);
    assert!(revocs.is_ok());
    let revocs = revocs.unwrap();
    assert_eq!(revocs.len(), 1);
}


#[test]
fn test_update_user_cert() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());

    // import key as new user
    let ctx_alice1 = make_context!();
    gnupg::create_user(&ctx_alice1, "alice@example.org");
    let alice1_key = gnupg::export(&ctx_alice1, &"alice@example.org");

    let alice1_file = format!("{}/alice1.key", home_path);
    std::fs::write(&alice1_file, alice1_key).expect("Unable to write file");

    ca.user_import(Some("Alice"), &vec!["alice@example.org"],
                   &alice1_file, None)
        .expect("import Alice 1 to CA failed");


    // import key as update to user key
    let ctx_alice2 = make_context!();
    gnupg::create_user(&ctx_alice2, "alice@example.org");
    let alice2_key = gnupg::export(&ctx_alice2, &"alice@example.org");

    let alice2_file = format!("{}/alice2.key", home_path);
    std::fs::write(&alice2_file, alice2_key).expect("Unable to write file");


    // get all users
    let users = ca.get_users("alice@example.org");
    assert!(users.is_ok());

    let users = users.unwrap();
    assert_eq!(users.len(), 1);

    let user = &users[0];

    // add updated cert
    let res = ca.user_add_cert(user.id, &alice2_file);
    assert!(res.is_ok());


    // check the state of CA data
    let users = ca.get_all_users();
    let users = users.unwrap();

    assert_eq!(users.len(), 1);

    let certs = ca.get_user_certs(&users[0]);
    assert!(certs.is_ok());

    let certs = certs.unwrap();

    // expect to find both user certs
    assert_eq!(certs.len(), 2);
}


#[test]
fn test_ca_insert_duplicate_email() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());


    // make CA user
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    // make CA user with the same email address
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(!res.is_ok());

    let users = ca.get_all_users();
    let users = users.unwrap();

    assert_eq!(users.len(), 1);
}
