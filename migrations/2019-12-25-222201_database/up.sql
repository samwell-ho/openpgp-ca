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

CREATE TABLE usercerts (
  id INTEGER NOT NULL PRIMARY KEY,
  updates_cert_id INTEGER, -- this is an update to an older usercert

  name VARCHAR,
  pub_cert VARCHAR NOT NULL,
  fingerprint VARCHAR NOT NULL,

  -- FIXME publish flag (wkd, ..?)
  -- FIXME user retired

  ca_id INTEGER NOT NULL,
  FOREIGN KEY(ca_id) REFERENCES cas(id) ON DELETE RESTRICT

  CONSTRAINT cert_fingerprint_unique UNIQUE (fingerprint)
);

CREATE TABLE emails (
  id INTEGER NOT NULL PRIMARY KEY,
  addr VARCHAR NOT NULL,

-- FIXME: n:m mapping to usercerts

  CONSTRAINT emails_addr_unique UNIQUE (addr)
);

-- n:m mapping  usercerts <-> emails
CREATE TABLE certs_emails (
  id INTEGER NOT NULL PRIMARY KEY,
  usercert_id INTEGER NOT NULL,
  email_id INTEGER NOT NULL,
  FOREIGN KEY(usercert_id) REFERENCES usercerts(id),
  FOREIGN KEY(email_id) REFERENCES emails(id)
);

-- revocations for user certs, user_ids, ...
CREATE TABLE revocations (
  id INTEGER NOT NULL PRIMARY KEY,
  revocation VARCHAR NOT NULL,
  published INTEGER NOT NULL, -- boolean value
  -- uid/keyid? -- FIXME
  -- subkey? -- FIXME
  -- reason -- FIXME
  -- expiration_time -- FIXME

  usercert_id INTEGER NOT NULL,
  FOREIGN KEY(usercert_id) REFERENCES usercerts(id)
);

CREATE TABLE bridges (
  id INTEGER NOT NULL PRIMARY KEY,
  email VARCHAR NOT NULL,
  scope VARCHAR NOT NULL,
  pub_key VARCHAR NOT NULL,

  cas_id INTEGER NOT NULL,

  FOREIGN KEY(cas_id) REFERENCES cas(id) ON DELETE RESTRICT,

  CONSTRAINT bridge_email_unique UNIQUE (email)
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
