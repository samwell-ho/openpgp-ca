Now that we've looked at OpenPGP CA's concepts, let's get started
using it.

# Installation

First, we install OpenPGP CA (or, alternatively, you can run OpenPGP CA
[in Docker](docker.md)).


As prerequisites, we need to install:

1. Rust and Cargo (see https://www.rust-lang.org/tools/install)

2. The C-dependencies of Sequoia PGP
   (see ["Building Sequoia"](https://gitlab.com/sequoia-pgp/sequoia))

Then we get the
[OpenPGP CA's source code](https://gitlab.com/openpgp-ca/openpgp-ca):

`$ git clone https://gitlab.com/openpgp-ca/openpgp-ca.git`

With all of the above in place, we can build the OpenPGP CA binary by
running the following command in the `openpgp-ca` source folder, which the `git clone` command created:
 
`$ cd openpgp-ca`
`$ cargo build --release`
 
To make sure everything is working right, you should also run the test suite.
Note: the integration tests call out to GnuPG to check that the data structures that
OpenPGP CA creates actually do what they are supposed to do.  Thus, you'll
need to have GnuPG installed to run the integration tests.

`$ cargo test`

Assuming the complication suceeded, the resulting binary will be called `target/release/openpgp-ca`.  

You can copy (or symlink) this binary to a directory that is in your
`$PATH`. If you do that, then you should be able to use OpenPGP CA as follows:

`$ openpgp-ca --help`


# Database

OpenPGP CA uses an SQLite database to keep track of its state.
This database is the only file that OpenPGP CA modifies, and the only file
that you need to backup to backup your CA.

You need to configure where this file is stored in the filesystem (there is
no default location). There are two ways to configure the database file:

1. You can set the `OPENPGP_CA_DB` environment variable.
2. Alternatively, the parameter `-d` sets the database file explicitly (this
   overrides the environment variable).
   
We're going to use the latter method in our examples.

If the configured database file doesn't exist, it will be created
implicitly.

## Multiple instances

If you operate multiple instances of OpenPGP CA, you can easily use
separate SQLite files: you just need one file per instance. You can then switch between
instances by setting the `OPENPGP_CA_DB` environment variable to
point to the correct database file for each instance or you can use the
explicit `-d` parameter.

## Offline instances, encryption

The OpenPGP CA database contains sensitive data: in particular, it
contains information about the users, it can contain revocation
certificates - and, most importantly, the private OpenPGP key of the
OpenPGP CA admin.

Because of this, the database file(s) needs to be protected. Depending on the
needs of your organization, this might mean storing the OpenPGP CA database
on encrypted storage, and/or running OpenPGP CA on an airgapped machine (that is,
one that is not connected to a network).  
OpenPGP CA's workflows have not yet been optimized for offline operation.
But, we intend to add support for this in the future.


# Help

If you're stuck, then you can use the "--help" option to get information about any command or subcommand, for instance:

`$ openpgp-ca --help`

or 

`$ openpgp-ca user --help`

or

`$ openpgp-ca user import --help`
