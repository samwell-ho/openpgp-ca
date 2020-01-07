# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys for users in their organization or in adjacent organizations.

OpenPGP CA is built using https://gitlab.com/sequoia-pgp/sequoia


## Building

OpenPGP CA requires:

- Rust and Cargo, see https://www.rust-lang.org/tools/install

- the C-dependencies of Sequoia PGP, see "Building Sequoia at" https://gitlab.com/sequoia-pgp/sequoia

Then run `cargo build --release` - the resulting binary is at `target/release/openpgp_ca`  

It's possible to run OpenPGP CA in Docker, [see below](#running-in-docker).

## General operation

### Database

OpenPGP CA uses an sqlite database to keep all of its state.

There are 3 ways of configuring while database file is user:

1.  the most common way is to set the `OPENPGP_CA_DB` environment variable
2.  the optional parameter "-d" overrides all other settings and sets the database file
3.  a `.env` file can set the environment variable `OPENPGP_CA_DB` "in the style of the ruby dotenv gem"

If the configured database file doesn't exist, it will get created implicitly.


### Help

The parameter "--help" will give information on any command level, e.g.

`openpgp_ca --help`

or 

`openpgp_ca user --help`

or

`openpgp_ca user import --help`


## Decentralized key creation workflow (user keys get generated on user machines, not by OpenPGP CA)

### (1) OpenPGP CA: set up, export CA public key

*  Set environment variable to configure where the database is stored:
 
`export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite`

*  Set up a new CA instance and generate a new keypair for the CA:

`openpgp_ca ca new example.org` 

*  Export the CA public key, for use on client machines:

`openpgp_ca ca export > ca.pubkey` 

### (2) On user machine using gpg: import CA public key, create new user

*  Set up a gpg test environment and import the CA public key:

`mkdir /tmp/test/`

`export GNUPGHOME=/tmp/test/`

`gpg --import ca.pubkey`

*  create and export a keypair (and optionally a revocation certificate) for
 Alice:

`gpg --quick-generate-key alice@example.org`

`gpg --export --armor alice@example.org > alice.pubkey`

`gpg --gen-revoke alice@example.org > alice-revocation.asc`

Alternatively, if your `gpg` generated a revocation certificate automagically (usually in `$GNUPGHOME/openpgp-revocs.d/<key_fingerprint>.rev`), you can use that, but remember to edit the file and remove the "`:`" at the beginning of the "`BEGIN PGP PUBLIC KEY BLOCK`" line.

*  tsign the CA public key with this key:

`gpg --edit-key openpgp-ca@example.org`

enter `tsign`, `2`, `250`, no domain (so just hit `Enter`), `y`, `save`.

*  export the signed CA public key:

`gpg --export --armor openpgp-ca@example.org > ca-tsigned.pubkey`

### (3) OpenPGP CA: import newly created user

*  copy the files `ca-tsigned.pubkey`, `alice.pubkey` and
 `alice-revocation.asc` so they are accessible for OpenPGP CA 

*  In OpenPGP CA, import Alice's key and revocation certificate - and Alice's
 trust signature on the CA key:

`openpgp_ca user import -n "Alice User" -e alice@example.org --key-file alice.pubkey --revocation-file alice-revocation.asc`

`openpgp_ca ca import-tsig --file ca-tsigned.pubkey`

*  Check OpenPGP CA's user list:

`openpgp_ca user list`

This should show that Alice's key has been signed by the CA and that Alice
 has made a trust signature on the CA public key  

*  Export Alice's public key (this includes the signature by the CA):

`openpgp_ca user export -e alice@example.org`


## Centralized key creation workflow (user keys get generated by OpenPGP CA)

### (1) OpenPGP CA:
#### set up CA

*  Set environment variable to configure where the database is stored:
 
`export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite`

*  Set up a new CA instance and generate a new keypair for the CA:

`openpgp_ca ca new example.org` 

#### create new user

`openpgp_ca user add -e alice@example.org -n "Alice User"`

The new user's private Key is shown as output of this command, but not
stored. It needs to be copied to the user's devices and imported into the
OpenPGP keystore there. We're going to paste the key into a file
`alice.privatekey` for this example.

#### export CA public key

*  Export the CA public key, for use on client machines (the key is tsigned
 by Alice at this point):

`openpgp_ca ca export > ca.pubkey` 

### (2) on user machine using gpg: import CA public key, user private key

*  Set up a gpg test environment and import the CA public key:

`mkdir /tmp/test/`

`export GNUPGHOME=/tmp/test/`

* Import user private key

`gpg --import alice.privatekey`

* Set ownertrust for this key

`gpg --edit-key alice@example.org`

Then `trust`, `5`, `quit`.

* Import CA public key

`gpg --import ca.pubkey`

* gpg now shows the Key for alice with "ultimate" trust, and the ca Key
 with "full" trust:
 
`gpg --list-keys` 

## Some random usage examples:

```
cargo run ca new example.org
cargo run -- -d /tmp/foo.sqlite ca new example.org

cargo run user add -e alice@example.org -e a@example.org -n Alicia
cargo run user add -e bob@example.org

cargo run user import -e heiko@example.org -n Heiko --key-file ~/heiko.pubkey
cargo run user import -e heiko@example.org -n Heiko --key-file _test_data/pubkey.asc --revocation-file _test_data/revoke.asc

cargo run bridge new -r "*@foo.de" --remote-key-file /tmp/bar.txt --name foobridge
cargo run bridge revoke --name foobridge

cargo run wkd-export /tmp/wkdtest/
```

## Running in Docker

You can also use `openpgp_ca` in [Docker](https://www.docker.com/). Building boils down to:

```
docker build --tag openpgp-ca ./
```

This will build the image and tag it as `openpgp-ca`. Once built, you can run it as:

```
docker run openpgp-ca
```

You should see the help output. Running any `openpgp_ca` command is easy, just add it at the end, like so:

```
docker run openpgp-ca ca new example.org
```

However, since it's running in Docker, the database does not persist. The database is kept in `/var/run/openpgp-ca/` inside the container. Therefore, you might want to do a volume-mount:

```
docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca ca new example.org
```

An example centralized workflow of creating a CA and a user would thus be:

```
docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca ca new example.org
docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user add -e alice@example.org -e a@example.org -n Alicia
docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user add -e bob@example.org
docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user list
```

Obviously for regular use you might use more automated tools like [`docker-compose`](https://docs.docker.com/compose/).
