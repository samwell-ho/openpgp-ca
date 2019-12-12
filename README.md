# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys for users in their organization or in adjacent organizations.

OpenPGP CA is built using https://gitlab.com/sequoia-pgp/sequoia


## General operation

### Database

OpenPGP CA uses an sqlite database to keep all of its state.

There are 3 ways of configuring while database file is user:

1.  the most common way is to set the ```OPENPGP_CA_DB``` environment variable
2.  the optional parameter "-d" overrides all other settings and sets the database file
3.  a ```.env``` file can set the environment variable ```OPENPGP_CA_DB``` "in the style of the ruby dotenv gem"

If the configured database file doesn't exist, it will get created implicitly.


### Help

The parameter "--help" will give information on any command level, e.g.

```openpgp_ca --help```

or 

```openpgp_ca user --help```

or

```openpgp_ca user import --help```


## example workflow: user keys get generated outside OpenPGP CA

### (1) OpenPGP CA: Set up, export CA public key

*  Set environment variable to configure where the database is stored:
 
```export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite```

*  Set up a new CA instance and generate a new keypair for the CA:

```openpgp_ca ca new ca@example.org``` 

*  Export the CA public key, for use on client machines:

```openpgp_ca ca export > ca.pubkey``` 

### (2) on user machine using gpg: import CA public key, create new user

*  Set up a gpg test environment and import the CA public key:

```mkdir /tmp/test/```

```export GNUPGHOME=/tmp/test/```

```gpg --import ca.pubkey```

*  create and export a keypair (and optionally a revocation certificate) for
 Alice:

```gpg --quick-generate-key alice@example.org```

```gpg --export --armor alice@example.org > alice.pubkey```

```gpg --gen-revoke alice@example.org > alice-revocation.asc```

*  tsign the CA public key with this key:

```gpg --edit-key ca@example.org```

enter ```tsign```, ```2```, ```250```, no domain, ```y```

*  export the signed CA public key:

```gpg --export --armor ca@example.org > ca-tsigned.pubkey```

### (3) OpenPGP CA: import newly created user

*  copy the files ```ca-signed.pubkey```, ```alice.pubkey``` and
 ```alice-revocation.asc``` so they are accessible for OpenPGP CA 

*  In OpenPGP CA, import Alice's key and revocation certificate - and Alice's
 trust signature on the CA key:

```openpgp_ca user import -n "Alice User" -e alice@example.org --key_file alice.pubkey -r alice-revocation.asc```

```openpgp_ca ca import-tsig --file ca-tsigned.pubkey```

*  Check OpenPGP CA's user list:

```openpgp_ca user list```

This should show that Alice's key has been signed by the CA and that Alice
 has made a trust signature on the CA public key  

*  Export Alice's public key (this includes the signature by the CA):

```openpgp_ca user export -e alice@example.org```

## Some random usage examples:

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
