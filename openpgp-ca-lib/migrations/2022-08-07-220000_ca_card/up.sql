-- SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- This file is part of OpenPGP CA
-- https://gitlab.com/openpgp-ca/openpgp-ca
--

-- Extend "cas" table: add columns for additional field "card"
ALTER TABLE cas
-- contains backend configuration, if the CA is not softkey-based
  ADD COLUMN backend VARCHAR;
