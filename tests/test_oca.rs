use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use openpgp_ca_lib::ca;

use openpgp_ca_lib::pgp;

mod gnupg;

#[test]
fn test_pgp_wrapper() {
    let (tpk, revoc) = pgp::Pgp::make_user(Some(&["foo@example.org"]))
        .unwrap();

    let x = pgp::Pgp::priv_cert_to_armored(&tpk);
    eprintln!("test tpk \n{}", x.unwrap());

//    let certkeys = pgp::Pgp::get_cert_keys(&tpk);
//
//    for key in certkeys.unwrap() {
//        eprintln!("keypair found");
//
//    }


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
    let res = ca.user_new(Some(&"Alice"), Some(&["alice@example.org"]));
    assert!(res.is_ok());

    let users = ca.get_users();

    println!("===================================================");

    for user in users.unwrap() {
        println!("user: {:?}", user.name);
        println!("{}", user.pub_key);
    }
}
