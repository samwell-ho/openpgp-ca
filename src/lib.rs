// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

//! This crate provides OpenPGP CA functionality as both a library and a
//! command line tool.

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

pub mod ca;
mod db;
mod models;
mod pgp;
mod schema;
