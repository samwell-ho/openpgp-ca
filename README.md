# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys for users in their organization or in adjacent organizations.

OpenPGP CA is built using https://gitlab.com/sequoia-pgp/sequoia


## General operation

### Database

OpenPGP CA uses an sqlite database to keep all of its state.

There are 3 ways of configuring while database file is user:

1) the most common way is to set the ```OPENPGP_CA_DB``` environment variable
2) the optional parameter "-d" overrides all other settings and sets the
   database file
3) a ```.env``` file can set the environment variable ```OPENPGP_CA_DB```
   "in the style of the ruby dotenv gem"

### Help

The parameter "--help" will give information on any command level, e.g.

```openpgp_ca --help```

or 

```openpgp_ca user --help```

or

```openpgp_ca user import --help```


## Usage examples:

```
cargo run ca new openpgp_ca@example.org
cargo run -- -d /tmp/foo.sqlite ca new openpgp_ca@example.org

cargo run user add -e alice@example.org -e a@example.org -n Alicia
cargo run user add -e bob@example.org

cargo run user import -e heiko@example.org -n Heiko --key_file ~/heiko.pubkey
cargo run user import -e heiko@example.org -n Heiko --key_file _test_data/pubkey.asc --revocation_file _test_data/revoke.asc

cargo run bridge new -r "*@foo.de" --remote_key_file /tmp/bar.txt --name foobridge
cargo run bridge revoke --name foobridge
```

A sqlite database gets created implicitly
(by default in /tmp/openpgpca.sqlite, as configured in the ".env" file in this project)