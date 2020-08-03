PRAGMA foreign_keys = ON;

CREATE TABLE cas (
  id INTEGER NOT NULL PRIMARY KEY,
  domainname VARCHAR NOT NULL
);

CREATE TABLE cacerts (
  id INTEGER NOT NULL PRIMARY KEY,
  cert VARCHAR NOT NULL,

  ca_id INTEGER NOT NULL,
  FOREIGN KEY(ca_id) REFERENCES cas(id)
);

CREATE TABLE users (
  id INTEGER NOT NULL PRIMARY KEY,
    name VARCHAR,

  -- FIXME publish flag (wkd, ..?)
  -- FIXME user retired

  ca_id INTEGER NOT NULL,
  FOREIGN KEY(ca_id) REFERENCES cas(id) ON DELETE RESTRICT
);

CREATE TABLE certs (
  id INTEGER NOT NULL PRIMARY KEY,

  fingerprint VARCHAR NOT NULL,
  pub_cert VARCHAR NOT NULL,

  CONSTRAINT cert_fingerprint_unique UNIQUE (fingerprint)
);

CREATE UNIQUE INDEX idx_certs_fingerprint
ON certs (fingerprint);

-- n:m mapping  users <-> certs
CREATE TABLE users_certs (
  id INTEGER NOT NULL PRIMARY KEY,

  user_id INTEGER NOT NULL,
  cert_id INTEGER NOT NULL,

  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(cert_id) REFERENCES certs(id)
);

CREATE INDEX idx_users_certs_user_id
ON users_certs (user_id);

CREATE INDEX idx_users_certs_cert_id
ON users_certs (cert_id);

CREATE TABLE emails (
  id INTEGER NOT NULL PRIMARY KEY,
  addr VARCHAR NOT NULL,

  CONSTRAINT emails_addr_unique UNIQUE (addr)
);

CREATE INDEX idx_emails_addr
ON emails (addr);

-- n:m mapping  certs <-> emails
CREATE TABLE certs_emails (
  id INTEGER NOT NULL PRIMARY KEY,

  cert_id INTEGER NOT NULL,
  email_id INTEGER NOT NULL,

  FOREIGN KEY(cert_id) REFERENCES certs(id),
  FOREIGN KEY(email_id) REFERENCES emails(id)
);

CREATE INDEX idx_certs_emails_cert_id
ON certs_emails (cert_id);

CREATE INDEX idx_certs_emails_email_id
ON certs_emails (email_id);

-- revocations for certs
CREATE TABLE revocations (
  id INTEGER NOT NULL PRIMARY KEY,
  hash VARCHAR NOT NULL,
  revocation VARCHAR NOT NULL,
  published BOOLEAN NOT NULL,
  -- uid/keyid? -- FIXME
  -- subkey? -- FIXME
  -- reason -- FIXME
  -- expiration_time -- FIXME

  cert_id INTEGER NOT NULL,
  FOREIGN KEY(cert_id) REFERENCES certs(id)
);

CREATE UNIQUE INDEX idx_revocations_hash
ON revocations (hash);

CREATE TABLE bridges (
  id INTEGER NOT NULL PRIMARY KEY,
  email VARCHAR NOT NULL,
  scope VARCHAR NOT NULL,
  pub_key VARCHAR NOT NULL,

  cas_id INTEGER NOT NULL,

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
