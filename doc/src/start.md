
Now that we've looked at the concepts of OpenPGP CA, let's get started
using it.

# Installation

First, we install OpenPGP CA (or, alternatively, you can run OpenPGP CA
[in Docker](docker.md)).


As prerequisites, we need to install:

1. Rust and Cargo (see https://www.rust-lang.org/tools/install)

2. The C-dependencies of Sequoia PGP
   (see ["Building Sequoia"](https://gitlab.com/sequoia-pgp/sequoia))

Then we get the
[OpenPGP-CA source-code](https://gitlab.com/openpgp-ca/openpgp-ca).

With all of the above in place, we can build the OpenPGP CA binary by
running the following command in the openpgp-ca source folder:
 
`$ cargo build --release`
 
The resulting binary is generated at `target/release/openpgp-ca`.  

You can simply copy (or symlink) this binary into a directory that is in
$PATH. With that, you can now run, for example:

`$ openpgp-ca --help`


# Database

OpenPGP CA uses an SQLite database to keep all of its state.
This database is the only file that OpenPGP CA modifies.

You need to configure where this file is stored in the filesystem (there is
no default location). There are two ways to configure the database file:

1. Usually, you'll want to set the `OPENPGP_CA_DB` environment variable.
2. Alternatively, the parameter "-d" sets the database file explicitly (this
   overrides the environment variable).

If the configured database file doesn't exist, it will get created
implicitly, and the schema will be generated in the database.

## Multiple instances

If you operate multiple instances of OpenPGP CA, you can easily use
separate SQLite files, one per instance. You can then switch between
instances by setting the `OPENPGP_CA_DB` environment variable to
point to the correct database file for each instance (or you can use the
explicit "-d" parameter).

## Offline instances, encryption

The OpenPGP CA database contains very valuable and sensitive data: it
contains information about our users, it can contain revocation
certificates - and, most importantly, the private OpenPGP key of the
OpenPGP CA admin.

Because of this, the database file(s) needs to be secured. Depending on the
needs of your organization, this might mean running OpenPGP CA on encrypted
storage, and/or running OpenPGP CA on an airgapped machine (that is not
 connected to any network at all). 


# Help

The parameter "--help" will give information on any command level, e.g.

`$ openpgp-ca --help`

or 

`$ openpgp-ca user --help`

or

`$ openpgp-ca user import --help`

