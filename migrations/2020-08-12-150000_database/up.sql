-- Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
--
-- This file is part of OpenPGP CA
-- https://gitlab.com/openpgp-ca/openpgp-ca
--
-- SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
-- SPDX-License-Identifier: GPL-3.0-or-later

PRAGMA foreign_keys = ON;

-- CA metadata
--
-- By convention, one OpenPGP CA database only
-- contains one row in this table.
--
-- To set up multiple CAs, multiple databases should be used.
CREATE TABLE cas (
  id INTEGER NOT NULL PRIMARY KEY,
  domainname VARCHAR NOT NULL,

  CONSTRAINT cas_domainname_unique UNIQUE (domainname)
);

-- Certificate(s) for the CA
--
-- This table may have multiple rows, if a CA cert is superseded by a new cert
CREATE TABLE cacerts (
  id INTEGER NOT NULL PRIMARY KEY,
  priv_cert VARCHAR NOT NULL,

  ca_id INTEGER NOT NULL,
  FOREIGN KEY(ca_id) REFERENCES cas(id)
);

-- User metadata
--
-- Each user can have one or many Certificates
CREATE TABLE users (
  id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR,

  -- FIXME publish flag (wkd, ..?)
  -- FIXME user retired

  ca_id INTEGER NOT NULL,
  FOREIGN KEY(ca_id) REFERENCES cas(id) ON DELETE RESTRICT
);

-- Certificates
--
-- Each certificate in this table is either associated with a user (via the
-- user_id foreign key), or pointed to by a bridge table row.
-- In the bridge case, the user_id field in this table is NULL.
CREATE TABLE certs (
  id INTEGER NOT NULL PRIMARY KEY,

  fingerprint VARCHAR NOT NULL,
  pub_cert VARCHAR NOT NULL,

  user_id INTEGER NULLABLE, -- null, if the cert belongs to a bridge
  FOREIGN KEY(user_id) REFERENCES users(id),

  CONSTRAINT cert_fingerprint_unique UNIQUE (fingerprint)
);

-- certs.fingerprint is used for lookups, so we generate an index
CREATE UNIQUE INDEX idx_certs_fingerprint
ON certs (fingerprint);

-- Each cert is connected to n email addresses, via this table
CREATE TABLE certs_emails (
  id INTEGER NOT NULL PRIMARY KEY,
  addr VARCHAR NOT NULL, -- not necessarily unique

  cert_id INTEGER NOT NULL,
  FOREIGN KEY(cert_id) REFERENCES certs(id)
);

-- Certs may be looked up via email addr, so we create an index
CREATE INDEX idx_emails_addr
ON certs_emails (addr);

-- Certs may be looked up via cert_id, so we create an index
CREATE INDEX idx_certs_emails_cert_id
ON certs_emails (cert_id);

-- Revocations for Certs
--
-- Each Cert may be associated with n revocation certificates in this table.
CREATE TABLE revocations (
  id INTEGER NOT NULL PRIMARY KEY,
  hash VARCHAR NOT NULL, --  an identifier to address individual revocations
  revocation VARCHAR NOT NULL,
  published BOOLEAN NOT NULL, -- set to `true` when a revocation certificate has been applied to the associated certificate

  -- uid/keyid? -- FIXME
  -- subkey? -- FIXME
  -- reason -- FIXME
  -- expiration_time -- FIXME

  cert_id INTEGER NOT NULL,
  FOREIGN KEY(cert_id) REFERENCES certs(id)
);

-- revocations.hash is used for lookups, so we generate an index
CREATE UNIQUE INDEX idx_revocations_hash
ON revocations (hash);

-- revocations.cert_id is used for lookups, so we generate an index
CREATE INDEX idx_revocations_cert_id
ON revocations (cert_id);

-- Bridges
--
-- When a bridge is configured, a row in this table represents the remote
-- OpenPGP CA instance.
CREATE TABLE bridges (
  id INTEGER NOT NULL PRIMARY KEY,

  email VARCHAR NOT NULL, -- the email address of the remote OpenPGP CA instance
  scope VARCHAR NOT NULL, -- specifies how the trust signature for the remote CA cert is scoped

  cert_id INTEGER NOT NULL,
  cas_id INTEGER NOT NULL,

  FOREIGN KEY(cert_id) REFERENCES certs(id),
  FOREIGN KEY(cas_id) REFERENCES cas(id) ON DELETE RESTRICT,

  CONSTRAINT bridge_email_unique UNIQUE (email)
);

--CREATE TABLE prefs (
--  id INTEGER NOT NULL PRIMARY KEY

  -- keygen defaults

  -- upload to keyserver [bool]
  -- upload to wkd [bool]
  -- wkd address (?)

  -- key/value store? (a.b.c... structure)
--);
