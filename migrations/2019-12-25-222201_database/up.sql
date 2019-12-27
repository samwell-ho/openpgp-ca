PRAGMA foreign_keys = ON;

CREATE TABLE cas (
  id INTEGER NOT NULL PRIMARY KEY,
  email VARCHAR NOT NULL
);


CREATE TABLE ca_certs (
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

CREATE TABLE user_certs (
  id INTEGER NOT NULL PRIMARY KEY,
  pub_cert VARCHAR NOT NULL,
  fingerprint VARCHAR NOT NULL,

  user_id INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id),

  CONSTRAINT cert_fingerprint_unique UNIQUE (fingerprint)
);

CREATE TABLE emails (
  id INTEGER NOT NULL PRIMARY KEY,
  addr VARCHAR NOT NULL,

-- FIXME: n:m mapping to user_certs

  CONSTRAINT emails_addr_unique UNIQUE (addr)
);

-- n:m mapping  user_certs <-> emails
CREATE TABLE certs_emails (
  id INTEGER NOT NULL PRIMARY KEY,
  user_cert_id INTEGER NOT NULL,
  email_id INTEGER NOT NULL,
  FOREIGN KEY(user_cert_id) REFERENCES user_certs(id),
  FOREIGN KEY(email_id) REFERENCES emails(id)
);

-- revocations for user certs, user_ids, ...
CREATE TABLE revocations (
  id INTEGER NOT NULL PRIMARY KEY,
  revocation VARCHAR NOT NULL,
  -- uid/keyid? -- FIXME
  -- subkey? -- FIXME
  -- reason -- FIXME
  -- expiration_time -- FIXME

  user_cert_id INTEGER NOT NULL,
  FOREIGN KEY(user_cert_id) REFERENCES user_certs(id)
);

CREATE TABLE bridges (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR NOT NULL,
  pub_key VARCHAR NOT NULL,

  cas_id INTEGER NOT NULL,

  FOREIGN KEY(cas_id) REFERENCES cas(id) ON DELETE RESTRICT,

  CONSTRAINT bridge_name_unique UNIQUE (name)
);

CREATE TABLE prefs (
  id INTEGER NOT NULL PRIMARY KEY

-- FIXME

  -- keygen defaults

  -- upload to keyserver [bool]
  -- upload to wkd [bool]
  -- wkd address (?)

  -- key/value store? (a.b.c... structure)
);
