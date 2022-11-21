// Copyright 2019-2022 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenPGP CA data types.

use sequoia_openpgp::packet::UserID;

/// Models which User IDs of a Cert have (or have not) been certified by a CA
pub struct CertificationStatus {
    pub certified: Vec<UserID>,
    pub uncertified: Vec<UserID>,
}
