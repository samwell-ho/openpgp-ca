// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use openpgp_ca_lib::ca::OpenpgpCa;
use openpgp_ca_lib::restd;
use openpgp_ca_lib::restd::client::Client;
use openpgp_ca_lib::restd::oca_json::{Action, Certificate, ReturnStatus};

use rocket::futures::prelude::future::{AbortHandle, Abortable};

pub mod gnupg;

const ALICE_CERT: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX419BRYJKwYBBAHaRw8BAQdAnfJuV3EHFAJ31D968YvLlAAu0YqUxySSJ1Lh
ZeFRGhiIiQQfFgoAOwWCX419BQWJBaSPvQMLCQcJEGzJHRdUZDEGAxUKCAKbAQIe
ARYhBLcCUD+7JL2xZWJweGzJHRdUZDEGAABrPAD/byicPJZ8jy1ltwVMhm4YGADa
9SrxXioiT0ekwmb/+OoA/3wtR2erbbRS8z7+2eQ7qrCoRWk/FRKL6aDv7GKHS3EC
tBFhbGljZUBleGFtcGxlLm9yZ4iMBBMWCgA+BYJfjX0FBYkFpI+9AwsJBwkQbMkd
F1RkMQYDFQoIApkBApsBAh4BFiEEtwJQP7skvbFlYnB4bMkdF1RkMQYAANv8AP9G
MadAR2b3JOLvoe4b5MWwg0aVGY49rvVx39sU6OWFiwEAlLo9zCq8++ClBIuZDZcB
5WYHX/eTUzyyWUV3D2Zsowy4MwRfjX0FFgkrBgEEAdpHDwEBB0DpdKcbcCQRWnXw
75pBIF2jXWJk9Yp4oSK+87F4xfgCWoj4BBgWCgCqBYJfjX0FBYkFpI+9CRBsyR0X
VGQxBgKbAgIeAXagBBkWCgAnBYJfjX0FCRCgJ8lVXt8OxhYhBONIP93aDZThvL4K
aaAnyVVe3w7GAAAWYwD9FX3JULe0K6IfcpxhP6sKfjx20NdXLXueX5fg9/D6Bt0B
AOf5L4ACGZPCNwSG90dUtA9DiYbFlJTs80OKQ8YjETIMFiEEtwJQP7skvbFlYnB4
bMkdF1RkMQYAAPt0AQC/vVwTx4TUbo4ustT7wJ/9Q60e/Kns2AQ+tfKBsLldqgEA
8qibe9f7xjlTz6KfohB3dHkJRQh8I+90PWpT4wMK6Aa4OARfjX0FEgorBgEEAZdV
AQUBAQdAuObJBQI6kR3a0zslOKqs2Ojav/Ssgt9fmREBZ/EAXnQDAQgJiIEEGBYK
ADMFgl+NfQUFiQWkj70JEGzJHRdUZDEGApsMAh4BFiEEtwJQP7skvbFlYnB4bMkd
F1RkMQYAAPC0AQCA+xFqHX8503ijkIg4nQntnUzi7r5tdi2t2MMRFpf2SgEAtNLD
Xof5uIAoYhwfZWuSg3ggQv4/JaxXO02UIQx4pQk=
=GU5p
-----END PGP PUBLIC KEY BLOCK-----"#;

const CAROL_PRIV_CERT: &str = r#"
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 4B89 C2EF 2CF2 B05D D3B4  6561 E59E 83D5 33FF 1822
Comment: carol@example.org

xVgEX52PFhYJKwYBBAHaRw8BAQdAeBt8mYIJjFdtZWCbjEM7aW+eLbwOoEyO4jca
k8FnMCQAAP4xeDH6t/4J0ZRO8WnAEYDXryXAv5v4wUO2oFIsdLOdlBLbwokEHxYK
ADsFgl+djxYFiQWkj70DCwkHCRDlnoPVM/8YIgMVCggCmwECHgEWIQRLicLvLPKw
XdO0ZWHlnoPVM/8YIgAAE1wA/0tAqAH8Cut13AzeUed7f3Ap1Wip5eefROgFhu35
RQ+LAP99qU8O4SWG/GqwTyGMzS4sv7R13jKOTAxqIQoHswhPAs0RY2Fyb2xAZXhh
bXBsZS5vcmfCjAQTFgoAPgWCX52PFgWJBaSPvQMLCQcJEOWeg9Uz/xgiAxUKCAKZ
AQKbAQIeARYhBEuJwu8s8rBd07RlYeWeg9Uz/xgiAABYEwD+O04abEjl3+syXXDH
ywxn49e/Qt+bRM9ZOhmcUf3wgR0BAKVXXnWwo86BRzVjpHDdczPEphr/QpxSljGS
/98mdroCx1gEX52PFhYJKwYBBAHaRw8BAQdAjO/nJ4PXwmjvtbtyrsOpqx2YmQv+
BTiNsIHvm8VEBucAAP41a7jnvucPc6wYAlN55gsvbisAAt+CWxIKGoQme9qkEw1Z
wsA4BBgWCgCqBYJfnY8WBYkFpI+9CRDlnoPVM/8YIgKbAgIeAXagBBkWCgAnBYJf
nY8WCRBbZN1Fkk+i6RYhBIzBMUhgtvuqYRCpb1tk3UWST6LpAAB40QEAotMDj6NB
AW6YKxFf+s97zi9EBi8HsCbg5JjuJsdlxU0BAPmfzVeHM+DGJI4vEh00NeRmp0wV
06iBwgBYxpjlmKUPFiEES4nC7yzysF3TtGVh5Z6D1TP/GCIAANIGAP9cxDzjcBUX
bxsll+QzpCrenR+K2yMBj2NDFiao0HXRcwD+K4c24l2zthL4vSwzMIYrfuWwQ5Oi
9c/X8FKxTQB2/QjHXQRfnY8WEgorBgEEAZdVAQUBAQdAET7RhTCWZ6gaAKn1xy9/
C6jWKkpkIBBjp+SihA1EuQwDAQgJAAD/VmoxPY4kVY0urmREIyrjWW0/qpFbMSHW
D9XWpEclqaAOS8KBBBgWCgAzBYJfnY8WBYkFpI+9CRDlnoPVM/8YIgKbDAIeARYh
BEuJwu8s8rBd07RlYeWeg9Uz/xgiAAB5TQEAvffwZaXUmb+KnADMXtDPTNyCih5S
p+gH+Ket/uaC6dQA/R5u0cZNF4A7piWf7G+L8u+oztvjhFjZEEWqpvo9RFcJ
=SyJn
-----END PGP PRIVATE KEY BLOCK-----"#;

fn start_restd(db: String) -> AbortHandle {
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let _ = Abortable::new(
        tokio::spawn(restd::run(Some(db)).launch()),
        abort_registration,
    );

    abort_handle
}

#[tokio::test(threaded_scheduler)]
async fn test_restd_checks() {
    let ctx = gnupg::make_context().unwrap();
    // ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // -- init OpenPGP CA --
    let ca = OpenpgpCa::new(Some(&db)).unwrap();
    ca.ca_init("example.org", None).unwrap();

    // -- start restd --
    let abort_handle = start_restd(db);

    let c = Client::new("http://localhost:8000/");

    // 1. Alice, Ok
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

    let res = c.check(&cert).await;
    assert!(res.is_ok());
    let ret = res.unwrap();
    assert!(ret.is_some());
    let ret = ret.unwrap();

    assert_eq!(ret.action, Some(Action::New));
    assert_eq!(
        ret.cert_info.fingerprint,
        "B702503FBB24BDB1656270786CC91D1754643106".to_string()
    );

    // 2a. Alice, uid/email mismatch
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice2@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

    let res = c.check(&cert).await;

    assert!(res.is_err());
    let ret = res.err().unwrap();
    assert_eq!(ret.status, ReturnStatus::KeyMissingLocalUserId);

    // 2b. Alice, bad email
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example@org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

    let res = c.check(&cert).await;

    assert!(res.is_err());
    let ret = res.err().unwrap();
    assert_eq!(ret.status, ReturnStatus::BadEmail);

    // 3. Carol, private key is bad
    let cert = Certificate {
        cert: CAROL_PRIV_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["carol@example.org".to_owned()],
        name: Some("Carol".to_owned()),
        revocations: vec![],
    };

    let res = c.check(&cert).await;

    assert!(res.is_err());
    let ret = res.err().unwrap();
    assert_eq!(ret.status, ReturnStatus::PrivateKey);

    // -- abort restd --
    abort_handle.abort();
}

#[tokio::test(threaded_scheduler)]
async fn test_restd_persist_retrieve() {
    let ctx = gnupg::make_context().unwrap();
    // ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // -- init OpenPGP CA --
    let ca = OpenpgpCa::new(Some(&db)).unwrap();
    ca.ca_init("example.org", None).unwrap();

    // -- start restd --
    let abort_handle = start_restd(db);

    let c = Client::new("http://localhost:8000/");

    // 1. Alice, Ok
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

    // check
    let res = c.check(&cert).await;
    assert!(res.is_ok());

    let res = res.unwrap().unwrap();
    let fp = res.cert_info.fingerprint;

    // persist
    let res = c.persist(&cert).await;
    assert!(res.is_ok());

    // look up by email
    let res = c.get_by_email("alice@example.org".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res.len(), 1);

    // email doesn't exist
    let res = c.get_by_email("bob@example.org".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res.len(), 0);

    // look up by fingerprint
    let res = c.get_by_fp(fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());

    // fingerprint doesn't exist
    let res = c.get_by_fp("123456".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_none());

    // => POST /certs/deactivate/<fp> (deactivate_cert)
    let res = c.deactivate(fp.clone()).await;
    assert!(res.is_ok());

    let res = c.get_by_fp(fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.certificate.inactive.unwrap());

    // => DELETE /certs/<fp> (delist_cert)
    let res = c.delist(fp.clone()).await;
    assert!(res.is_ok());

    let res = c.get_by_fp(fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.certificate.delisted.unwrap());

    // -- abort restd --
    abort_handle.abort();
}
