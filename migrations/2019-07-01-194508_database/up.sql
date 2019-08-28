PRAGMA foreign_keys = ON;

CREATE TABLE cas (
  id INTEGER NOT NULL PRIMARY KEY,
  -- bridges [foreign key]
  name VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  ca_key VARCHAR NOT NULL,
  revoc_cert VARCHAR NOT NULL,
  -- upload to keyserver [bool]
  -- upload to wkd [bool]
  -- wkd address (?)

  CONSTRAINT ca_name_unique UNIQUE (name)
);

CREATE TABLE users (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR,
  pub_key VARCHAR NOT NULL,
  revoc_cert VARCHAR,

  cas_id INTEGER NOT NULL,

  FOREIGN KEY(cas_id) REFERENCES cas(id) ON DELETE RESTRICT
);

CREATE TABLE emails (
  id INTEGER NOT NULL PRIMARY KEY,
  addr VARCHAR NOT NULL,

  user_id INTEGER NOT NULL,

  FOREIGN KEY(user_id) REFERENCES users(id),

  CONSTRAINT emails_addr_unique UNIQUE (addr)
);

CREATE TABLE bridges (
  id INTEGER NOT NULL PRIMARY KEY,
  name VARCHAR NOT NULL,
  pub_key VARCHAR NOT NULL,

  cas_id INTEGER NOT NULL,

  FOREIGN KEY(cas_id) REFERENCES cas(id) ON DELETE RESTRICT

  CONSTRAINT bridge_name_unique UNIQUE (name)
);
