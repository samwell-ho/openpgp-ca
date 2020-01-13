use openpgp_ca_lib::ca;
use openpgp_ca_lib::pgp;
use std::path::Path;
use std::time::SystemTime;
use failure::_core::time::Duration;

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
    assert!(ca.ca_new("example.org").is_ok());


    // make CA user
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    let usercerts = ca.get_all_usercerts();
    let usercerts = usercerts.unwrap();

    assert_eq!(usercerts.len(), 1);

    let usercert = &usercerts[0];
    let emails = ca.get_emails(usercert);

    assert!(emails.is_ok());
    let emails = emails.unwrap();
    assert_eq!(emails.len(), 1);

    let revocs = ca.get_revocations(usercert);
    assert!(revocs.is_ok());
    let revocs = revocs.unwrap();
    assert_eq!(revocs.len(), 1);
}


#[test]
fn test_update_usercert_key() {
    let now = SystemTime::now();
    let in_one_year =
        now.checked_add(Duration::from_secs(3600 * 24 * 365 * 1));
    let in_three_years =
        now.checked_add(Duration::from_secs(3600 * 24 * 365 * 3));
    let in_six_years =
        now.checked_add(Duration::from_secs(3600 * 24 * 365 * 6));

    // update key with new version, but same fingerprint
    let mut ctx = make_context!();
    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new("example.org").is_ok());

    // import key as new user
    gnupg::create_user(&ctx, "alice@example.org");
    let alice1_key = gnupg::export(&ctx, &"alice@example.org");

    let alice1_file = format!("{}/alice1.key", home_path);
    std::fs::write(&alice1_file, alice1_key).expect("Unable to write file");

    ca.usercert_import(Some("Alice"), &vec!["alice@example.org"],
                       &alice1_file, None)
        .expect("import Alice 1 to CA failed");


    // check the state of CA data
    let usercerts = ca.get_all_usercerts();
    let usercerts = usercerts.unwrap();

    assert_eq!(usercerts.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = pgp::Pgp::armored_to_cert(&usercerts[0].pub_cert);

    assert!(cert.alive(in_one_year).is_ok());
    assert!(!cert.alive(in_three_years).is_ok());

    // edit key with gpg, then import new version into CA
    gnupg::edit_expire(&ctx, "alice@example.org", "5y");
    let alice2_key = gnupg::export(&ctx, &"alice@example.org");

    let alice2_file = format!("{}/alice2.key", home_path);
    std::fs::write(&alice2_file, alice2_key).expect("Unable to write file");


    // get usercert for alice
    let usercerts = ca.get_usercerts("alice@example.org");
    assert!(usercerts.is_ok());

    let usercerts = usercerts.unwrap();
    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // store updated version of cert
    let res = ca.usercert_import_update(alice, &alice2_file);


    // check the state of CA data
    let usercerts = ca.get_all_usercerts();
    let usercerts = usercerts.unwrap();

    assert_eq!(usercerts.len(), 1);

    // check that expiry is not ~2y but ~5y
    let cert = pgp::Pgp::armored_to_cert(&usercerts[0].pub_cert);

    assert!(cert.alive(in_three_years).is_ok());
    assert!(!cert.alive(in_six_years).is_ok());
}

#[test]
fn test_update_user_cert() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new("example.org").is_ok());

    // import key as new user
    let ctx_alice1 = make_context!();
    gnupg::create_user(&ctx_alice1, "alice@example.org");
    let alice1_key = gnupg::export(&ctx_alice1, &"alice@example.org");

    let alice1_file = format!("{}/alice1.key", home_path);
    std::fs::write(&alice1_file, alice1_key).expect("Unable to write file");

    ca.usercert_import(Some("Alice"), &vec!["alice@example.org"],
                       &alice1_file, None)
        .expect("import Alice 1 to CA failed");


    // import key as update to user key
    let ctx_alice2 = make_context!();
    gnupg::create_user(&ctx_alice2, "alice@example.org");
    let alice2_key = gnupg::export(&ctx_alice2, &"alice@example.org");

    let alice2_file = format!("{}/alice2.key", home_path);
    std::fs::write(&alice2_file, alice2_key).expect("Unable to write file");


    // get usercert for alice
    let usercerts = ca.get_usercerts("alice@example.org");
    assert!(usercerts.is_ok());

    let usercerts = usercerts.unwrap();
    assert_eq!(usercerts.len(), 1);

    let alice = &usercerts[0];

    // store updated version of cert
    let res = ca.usercert_import_update(alice, &alice2_file);

    println!("{:?}", res);
    assert!(res.is_ok());


    // check the state of CA data
    let usercerts = ca.get_all_usercerts();
    let usercerts = usercerts.unwrap();

    assert_eq!(usercerts.len(), 2);

    // FIXME: add method to filter for "current" usercerts, or similar?!

//    let certs = ca.get_user_certs(&usercerts[0]);
//    assert!(certs.is_ok());
//
//    let certs = certs.unwrap();
//
//    // expect to find both user certs
//    assert_eq!(certs.len(), 2);
}


#[test]
fn test_ca_insert_duplicate_email() {
    // two usercerts with the same email are considered distinct certs
    // (e.g. "normal cert" vs "code signing cert")

    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new("example.org").is_ok());


    // make CA user
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    // make another CA user with the same email address
    let res = ca.user_new(Some(&"Alice"), &["alice@example.org"]);
    assert!(res.is_ok());

    let usercerts = ca.get_all_usercerts();
    let usercerts = usercerts.unwrap();

    assert_eq!(usercerts.len(), 2);

    // ca cert should be tsigned by all usercerts
    for uc in &usercerts {
        let res = ca.check_ca_has_tsig(&uc);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}


#[test]
fn test_ca_export_wkd() {
    let ctx = make_context!();
//    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    let mut ca = ca::Ca::new(Some(&db));

    assert!(ca.ca_new("example.org").is_ok());
    assert!(ca.user_new(Some(&"Alice"), &["alice@example.org"]).is_ok());
    assert!(ca.user_new(Some(&"Bob"), &["bob@example.org"]).is_ok());

    let wkd_dir = home_path + "/wkd/";
    let wkd_path = Path::new(&wkd_dir);

    let res = ca.export_wkd("example.org", &wkd_path);
    assert!(res.is_ok());


    // check that both user keys have been written to files
    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/jycbiujnsxs47xrkethgtj69xuunurok");
    assert!(test_path.is_file());

    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/kei1q4tipxxu1yj79k9kfukdhfy631xe");
    assert!(test_path.is_file());


    // check that CA key has been written to file
    let test_path = wkd_path.join(
        "openpgpkey.example.org/.well-known/openpgpkey/example.org\
         /hu/ermf4k8pujzwtqqxmskb7355sebj5e4t");
    assert!(test_path.is_file());
}