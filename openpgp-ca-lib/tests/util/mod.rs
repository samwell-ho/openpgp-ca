// SPDX-FileCopyrightText: 2019-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

use openpgp_ca_lib::Uninit;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::state::Open;
use openpgp_card_sequoia::Card;
use sequoia_openpgp::Fingerprint;

#[allow(dead_code)]
pub(crate) mod gnupg_test_wrapper;

#[allow(dead_code)]
pub(crate) fn reset_card(ident: &str) -> anyhow::Result<()> {
    let backend = PcscBackend::open_by_ident(ident, None)?;
    let mut open: Card<Open> = backend.into();

    let mut card = open.transaction()?;
    card.factory_reset().map_err(|e| anyhow::anyhow!(e))
}

/// Get the AUT slot fingerprint from the card 'ident'
#[allow(dead_code)]
pub(crate) fn card_auth_slot_fingerprint(ident: &str) -> anyhow::Result<Fingerprint> {
    let backend = PcscBackend::open_by_ident(ident, None)?;
    let mut open: Card<Open> = backend.into();
    let card = open.transaction()?;

    let auth_fp = card
        .fingerprints()?
        .authentication()
        .ok_or_else(|| anyhow::anyhow!("No fingerprint in AUT slot"))?
        .to_spaced_hex();

    auth_fp.parse()
}

#[allow(dead_code)]
pub(crate) fn setup_one_uninit() -> anyhow::Result<(gnupg_test_wrapper::Ctx, Uninit)> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let mut home_path = gpg.get_homedir().to_path_buf();
    home_path.push("ca.sqlite");

    assert!(home_path.to_str().is_some());

    let cau = Uninit::new(home_path.to_str())?;

    Ok((gpg, cau))
}

#[allow(dead_code)]
pub(crate) fn setup_two_uninit() -> anyhow::Result<(gnupg_test_wrapper::Ctx, Uninit, Uninit)> {
    let gpg = gnupg_test_wrapper::make_context()?;

    let mut db1 = gpg.get_homedir().to_path_buf();
    db1.push("ca1.sqlite");
    let mut db2 = gpg.get_homedir().to_path_buf();
    db2.push("ca2.sqlite");

    assert!(db1.to_str().is_some());
    assert!(db2.to_str().is_some());

    let ca1u = Uninit::new(db1.to_str())?;
    let ca2u = Uninit::new(db2.to_str())?;

    Ok((gpg, ca1u, ca2u))
}

#[allow(dead_code)]
pub(crate) fn setup_three_uninit(
) -> anyhow::Result<(gnupg_test_wrapper::Ctx, Uninit, Uninit, Uninit)> {
    let gpg = gnupg_test_wrapper::make_context()?;

    // don't delete home dir (for manual inspection)
    // gpg.leak_tempdir();

    let mut db1 = gpg.get_homedir().to_path_buf();
    db1.push("ca1.sqlite");
    let mut db2 = gpg.get_homedir().to_path_buf();
    db2.push("ca2.sqlite");
    let mut db3 = gpg.get_homedir().to_path_buf();
    db3.push("ca3.sqlite");

    assert!(db1.to_str().is_some());
    assert!(db2.to_str().is_some());
    assert!(db3.to_str().is_some());

    let ca1u = Uninit::new(db1.to_str())?;
    let ca2u = Uninit::new(db2.to_str())?;
    let ca3u = Uninit::new(db3.to_str())?;

    Ok((gpg, ca1u, ca2u, ca3u))
}
