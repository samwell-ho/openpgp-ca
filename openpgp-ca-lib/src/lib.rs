// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! This crate provides OpenPGP CA functionality as both a library and a
//! command line tool.

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

mod bridge;
pub mod ca;
mod ca_secret;
mod cert;
pub mod db;
mod export;
pub mod pgp;
mod revocation;
mod update;
