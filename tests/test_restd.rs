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

/// a new key for alice
const ALICE2_CERT: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX6Rh8xYJKwYBBAHaRw8BAQdAzpHTtV3+LepFIn5www3Z3z7nDSEOxh1tZ/rg
vccdjwuIiQQfFgoAOwWCX6Rh8wWJBaSPvQMLCQcJEEyOtxj0Q7k7AxUKCAKbAQIe
ARYhBFORdK92TKEb8hk4gkyOtxj0Q7k7AACSwAD8DrtlXFsN/NTA9RmtSJBorOVX
aNkrl4wRz43m+ZeXwnwBAJK0oK6poHQHirTXBBJQ1JXtGVc6Eb1JJpQ/lkO19L0O
tBFhbGljZUBleGFtcGxlLm9yZ4iMBBMWCgA+BYJfpGHzBYkFpI+9AwsJBwkQTI63
GPRDuTsDFQoIApkBApsBAh4BFiEEU5F0r3ZMoRvyGTiCTI63GPRDuTsAAI7GAP9r
qvNrDjr2Jtq2ggRvPePVtlnb+x8g943s5y2wf+0ClQD7BK2teJTYS2qUAh8iVoai
8k3gw2Yh6oAkc5A/mqXl9Qe4MwRfpGHzFgkrBgEEAdpHDwEBB0BkZ6AezyTzNCl2
IiWs43vwAA26FHFbxTbp95S6k9sv0oj4BBgWCgCqBYJfpGHzBYkFpI+9CRBMjrcY
9EO5OwKbAgIeAXagBBkWCgAnBYJfpGHzCRA/5xILdVRnPhYhBAOuZXmgZELrUJvt
4D/nEgt1VGc+AAAJFwEAtlANerYj0qLqvVKGThOScrzIkQsJXExFZRZiF+1IdfwB
AIaYVN0yBLiiYRGtsO8yN7oTyKw47hNJ3G8qO4yNg5IMFiEEU5F0r3ZMoRvyGTiC
TI63GPRDuTsAAOR6AP4j9l7OQAgr4V2SL0ZOnfDHXgzdD+orHqAc7P6m2RJXcgD/
ZXaUFYz5R5PhxFXG3jFBBz4tOPAV6PQWtiAOMS/ztQm4OARfpGHzEgorBgEEAZdV
AQUBAQdAFIfvXJGeIlDQR754ejoIXEBX8/nt/issujJ1toFGolgDAQgJiIEEGBYK
ADMFgl+kYfMFiQWkj70JEEyOtxj0Q7k7ApsMAh4BFiEEU5F0r3ZMoRvyGTiCTI63
GPRDuTsAAGZdAP9EkFpq6dxan5f/FFYPLUES0LFlajgng55fXYGoB1OfmAD+PFpg
Dqg1p7Zspq9rTz0To6a8vwOg6ITgMoOvZoSnSQk=
=UoAJ
-----END PGP PUBLIC KEY BLOCK-----"#;

/// alice has revoked her new key, this update includes the revocation
const ALICE2_CERT_REV: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX6Rh8xYJKwYBBAHaRw8BAQdAzpHTtV3+LepFIn5www3Z3z7nDSEOxh1tZ/rg
vccdjwuIiQQgFggAMRYhBFORdK92TKEb8hk4gkyOtxj0Q7k7BQJfpGQ1Ex0DS2V5
IGlzIG91dCBvZiB1c2UACgkQTI63GPRDuTv1egEAkPd+ee6uHHo5haiQFvnF/cyL
d7tytKblP+pIQhNyiwkA/0UD6CuAWiwP/j1G3narA58YpWlCNuLJirIVxn6jojsA
iIkEHxYKADsFgl+kYfMFiQWkj70DCwkHCRBMjrcY9EO5OwMVCggCmwECHgEWIQRT
kXSvdkyhG/IZOIJMjrcY9EO5OwAAksAA/A67ZVxbDfzUwPUZrUiQaKzlV2jZK5eM
Ec+N5vmXl8J8AQCStKCuqaB0B4q01wQSUNSV7RlXOhG9SSaUP5ZDtfS9DrQRYWxp
Y2VAZXhhbXBsZS5vcmeIhgQTFgoALgMLCQcDFQoIApkBApsBAh4BFiEEU5F0r3ZM
oRvyGTiCTI63GPRDuTsFAl+kYqUACgkQTI63GPRDuTtEMwD+OWIF5BfQ+AiKU1jf
9mMWjsacGnqwvubsOdbYGJG5oFgA/A74l77pFaww2rrU8CxOQeSowrG3AL4yOMmI
RkaJxOgFiIwEExYKAD4Fgl+kYfMFiQWkj70DCwkHCRBMjrcY9EO5OwMVCggCmQEC
mwECHgEWIQRTkXSvdkyhG/IZOIJMjrcY9EO5OwAAjsYA/2uq82sOOvYm2raCBG89
49W2Wdv7HyD3jeznLbB/7QKVAPsEra14lNhLapQCHyJWhqLyTeDDZiHqgCRzkD+a
peX1B7gzBF+kYfMWCSsGAQQB2kcPAQEHQGRnoB7PJPM0KXYiJazje/AADboUcVvF
Nun3lLqT2y/SiPgEGBYKAKoFgl+kYfMFiQWkj70JEEyOtxj0Q7k7ApsCAh4BdqAE
GRYKACcFgl+kYfMJED/nEgt1VGc+FiEEA65leaBkQutQm+3gP+cSC3VUZz4AAAkX
AQC2UA16tiPSouq9UoZOE5JyvMiRCwlcTEVlFmIX7Uh1/AEAhphU3TIEuKJhEa2w
7zI3uhPIrDjuE0ncbyo7jI2DkgwWIQRTkXSvdkyhG/IZOIJMjrcY9EO5OwAA5HoA
/iP2Xs5ACCvhXZIvRk6d8MdeDN0P6iseoBzs/qbZEldyAP9ldpQVjPlHk+HEVcbe
MUEHPi048BXo9Ba2IA4xL/O1Cbg4BF+kYfMSCisGAQQBl1UBBQEBB0AUh+9ckZ4i
UNBHvnh6OghcQFfz+e3+Kyy6MnW2gUaiWAMBCAmIgQQYFgoAMwWCX6Rh8wWJBaSP
vQkQTI63GPRDuTsCmwwCHgEWIQRTkXSvdkyhG/IZOIJMjrcY9EO5OwAAZl0A/0SQ
Wmrp3Fqfl/8UVg8tQRLQsWVqOCeDnl9dgagHU5+YAP48WmAOqDWntmymr2tPPROj
pry/A6DohOAyg69mhKdJCQ==
=vN+R
-----END PGP PUBLIC KEY BLOCK-----"#;

const BOB_CERT: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX6Rg/xYJKwYBBAHaRw8BAQdA9XMnwHWQ028OmnBiO7L5nydlDXwtFeGVWfcF
G3KNcQaIiQQfFgoAOwWCX6Rg/wWJBaSPvQMLCQcJEP5l7QLpv9x/AxUKCAKbAQIe
ARYhBPq7gUDt8RcF7rSwhv5l7QLpv9x/AAARtAEAhDQkKUN2ULX+Hl6u3B5/dtkF
yJ3yZT97MWI+92IT3E4BALW7EiUcGnhZgQvyaH/7YXskOR2p5P/Na6Yz9ffEraQP
tA9ib2JAZXhhbXBsZS5vcmeIjAQTFgoAPgWCX6Rg/wWJBaSPvQMLCQcJEP5l7QLp
v9x/AxUKCAKZAQKbAQIeARYhBPq7gUDt8RcF7rSwhv5l7QLpv9x/AADShQEAy3Bq
QasCIVLzYQ5bjhk2t6/4Tbzk8OMCEmZF29unok4A/3qid8qjssdjgyk4DLSomtUS
5vVxEOfHp5S6Supkt0wIuDMEX6Rg/xYJKwYBBAHaRw8BAQdAkYkyyMoVdfMIU03t
tmUbY+Fn+n3mJBK0nTZR9p9oxSSI+AQYFgoAqgWCX6Rg/wWJBaSPvQkQ/mXtAum/
3H8CmwICHgF2oAQZFgoAJwWCX6Rg/wkQuuWsp+4oBeUWIQRCq2A0Bh7NiRGz9jy6
5ayn7igF5QAAPKoA/j+lub0yjiGZ50Qx2C1hGQ6EN/qgBUU2j5sKU/YlMrdGAPoC
fRKfXdfw+ULzpHPUmb+WF42WNBhn4m+SWF+aM8f5BxYhBPq7gUDt8RcF7rSwhv5l
7QLpv9x/AABS3gEA/BiG9uqZLa9lvW49W4fDU7FwMfaOZ2Qm9LqidFGu5eABAKLK
S035QBDnwe4Zrum6FM5IQcB+8WhlACbw8dsEI+4AuDgEX6Rg/xIKKwYBBAGXVQEF
AQEHQGww6k4jqbTj9abgWGlOGxQcaoE+dnGc1kA667iR9cMFAwEICYiBBBgWCgAz
BYJfpGD/BYkFpI+9CRD+Ze0C6b/cfwKbDAIeARYhBPq7gUDt8RcF7rSwhv5l7QLp
v9x/AABUQAEA0y+EauezWO15y9YF3WVP3Vo3y3440bVgGroFESvYNiMA/j1fQw+z
1J1fMrMiChFW8w120+NEObmVOlG6fSODWMwD
=XZQz
-----END PGP PUBLIC KEY BLOCK-----"#;

/// this is a private key, it's an error to provide it to this service
const CAROL_PRIV_CERT: &str = r#"-----BEGIN PGP PRIVATE KEY BLOCK-----
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
async fn test_restd() {
    // Run all "restd" tests in one test-case.
    //
    // Running multiple restd-tests in parallel leads to errors when
    // multiple rocket daemons try to bind to the same tcp port.

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

    // --- Various "check" calls ---

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

    let alice_fp = ret.cert_info.fingerprint.clone();

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

    // --- Persist, Modify, Read ---
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

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
    let res = c.get_by_fp(alice_fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());

    // fingerprint doesn't exist
    let res = c.get_by_fp("123456".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_none());

    // => POST /certs/deactivate/<fp> (deactivate_cert)
    let res = c.deactivate(alice_fp.clone()).await;
    assert!(res.is_ok());

    let res = c.get_by_fp(alice_fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.certificate.inactive.unwrap());

    // => DELETE /certs/<fp> (delist_cert)
    let res = c.delist(alice_fp.clone()).await;
    assert!(res.is_ok());

    let res = c.get_by_fp(alice_fp.clone()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.is_some());
    let res = res.unwrap();
    assert!(res.certificate.delisted.unwrap());

    // 4. persist key for bob; a new key for alice, an update for alice's key

    let cert = Certificate {
        cert: BOB_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["bob@example.org".to_owned()],
        name: Some("Bob Baker".to_owned()),
        revocations: vec![],
    };
    let res = c.persist(&cert).await;
    assert!(res.is_ok());

    let cert = Certificate {
        cert: ALICE2_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };
    let res = c.persist(&cert).await;
    assert!(res.is_ok());

    let cert = Certificate {
        cert: ALICE2_CERT_REV.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };
    let res = c.persist(&cert).await;
    assert!(res.is_ok());

    // assert that there are now 2 entries for "alice@example.org"
    let res = c.get_by_email("alice@example.org".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res.len(), 2);

    // FIXME: check that the new key is considered revoked

    // ... and 1 entry for "bob@example.org"
    let res = c.get_by_email("bob@example.org".into()).await;
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res.len(), 1);

    // -- abort restd --
    abort_handle.abort();
}
