-- Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
--
-- This file is part of OpenPGP CA
-- https://gitlab.com/openpgp-ca/openpgp-ca
--
-- SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
-- SPDX-License-Identifier: GPL-3.0-or-later

-- Extend "certs" table:
-- add columns for additional fields "delisted" and "inactive"
ALTER TABLE certs
-- 'true' when a cert should not be exported [to WKD and similar]
  ADD COLUMN delisted BOOLEAN NOT NULL DEFAULT false;

-- 'true' when CA certifications should not be refreshed anymore
ALTER TABLE certs
  ADD COLUMN inactive BOOLEAN NOT NULL DEFAULT false;
