use sequoia_openpgp as openpgp;
use openpgp::serialize::Serialize;

use openpgp_ca_lib::ca;

mod tools;

use tools::Context;
use tools::gpg_import;

#[test]
fn run_gpg() {
    let ctx = make_context!();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/db.sqlite", home_path);

    let ca = ca::Ca::new(Some(&db));

    // make new CA key
    assert!(ca.ca_new(&["ca@example.org"]).is_ok());

    // get TPK for CA
    let ca_tpk = ca.get_ca_key();
    assert!(ca_tpk.is_ok());

    let mut buf = Vec::new();
    let tpk = ca_tpk.unwrap();
    tpk.as_tsk().serialize(&mut buf).unwrap();
    gpg_import(&ctx, &buf);

    assert!(true);
}
