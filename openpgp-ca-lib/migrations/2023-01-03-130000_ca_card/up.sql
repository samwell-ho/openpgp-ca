-- SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- This file is part of OpenPGP CA
-- https://gitlab.com/openpgp-ca/openpgp-ca
--

-- Extend "cacerts" table: add columns for backend
ALTER TABLE cacerts
-- contains backend configuration, if the CA is not softkey-based
  ADD COLUMN backend VARCHAR;
