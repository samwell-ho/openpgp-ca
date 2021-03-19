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

#[macro_use]
extern crate rocket;

mod bridge;
pub mod ca;
mod db;
mod export;
pub mod models;
mod pgp;
mod revocation;
mod schema;

pub mod restd;
