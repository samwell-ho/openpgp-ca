// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use anyhow::Result;
use tempfile::TempDir;

mod util;

#[test]
fn split_certify() -> Result<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.into_path();

    let mut csr_file = tmp_path.clone();
    csr_file.push("csr.txt");

    let mut sigs_file = tmp_path;
    sigs_file.push("certs.txt");

    let (_gpg, cau1, cau2) = util::setup_two_uninit()?;

    // Make new backing CA
    let ca1 = cau1.init_softkey("example.org", None)?;
    let ca_cert = ca1.ca_get_pubkey_armored()?;

    // Make new split-mode online CA with the same pubkey
    let ca2 = cau2.init_split_front("example.org", ca_cert.as_bytes())?;

    // Make user on online ca
    ca2.user_new(Some("Alice"), &["alice@example.org"], None, false, false)?;

    let certs = ca2.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = ca2.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 0);
    assert_eq!(alice.uncertified.len(), 1);

    // Ask backing ca1 to certify alice

    ca2.ca_split_export(csr_file.clone())?;
    ca1.ca_split_process(csr_file, sigs_file.clone())?;
    ca2.ca_split_import(sigs_file)?;

    let certs = ca2.user_certs_get_all()?;
    assert_eq!(certs.len(), 1);

    let cert = &certs[0];

    let alice = ca2.cert_check_ca_sig(cert)?;
    assert_eq!(alice.certified.len(), 1);
    assert_eq!(alice.uncertified.len(), 0);

    Ok(())
}
