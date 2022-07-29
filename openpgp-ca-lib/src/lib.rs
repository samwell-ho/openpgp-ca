// SPDX-FileCopyrightText: 2019-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca

//! This crate provides OpenPGP CA functionality as both a library and a
//! command line tool.

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod bridge;
pub mod ca;
mod ca_secret;
mod cert;
pub mod db;
mod export;
pub mod pgp;
mod revocation;
mod update;
