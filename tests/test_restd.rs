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
use openpgp_ca_lib::restd::oca_json::{Action, Certificate};

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

#[tokio::test(threaded_scheduler)]
async fn test_check_good_cert() {
    let mut ctx = gnupg::make_context().unwrap();
    ctx.leak_tempdir();

    let home_path = String::from(ctx.get_homedir().to_str().unwrap());
    let db = format!("{}/ca.sqlite", home_path);

    // -- init OpenPGP CA --
    let ca = OpenpgpCa::new(Some(&db)).unwrap();
    ca.ca_init("example.org", None).unwrap();

    // -- start restd --
    let (abort_handle, abort_registration) = AbortHandle::new_pair();
    let _ = Abortable::new(
        tokio::spawn(restd::run(Some(db)).launch()),
        abort_registration,
    );

    // -- do rest-client calls --
    let cert = Certificate {
        cert: ALICE_CERT.to_owned(),
        delisted: None,
        inactive: None,
        email: vec!["alice@example.org".to_owned()],
        name: Some("Alice Adams".to_owned()),
        revocations: vec![],
    };

    let c = Client::new("http://localhost:8000/");
    let res = c.check(&cert).await;

    // -- assertions --
    assert!(res.is_ok());

    let ret = res.unwrap();

    println!("{:?}", ret);

    assert_eq!(ret.action, Some(Action::New));
    assert_eq!(
        ret.cert_info.fingerprint,
        "B702503FBB24BDB1656270786CC91D1754643106".to_string()
    );

    // -- abort restd --
    abort_handle.abort();
}
