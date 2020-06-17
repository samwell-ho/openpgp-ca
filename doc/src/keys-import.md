# Decentralized key creation workflow
 
User keys get generated on user machines, not by OpenPGP CA

## Part 1: OpenPGP CA admin: set up, export CA public key

*  Set environment variable to configure where the database is stored:
 
`$ export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite`

*  Set up a new CA instance and generate a new keypair for the CA:

`$ openpgp-ca ca init example.org` 

*  Export the CA public key, for use on client machines:

`$ openpgp-ca ca export > ca.pubkey` 

## Part 2: On user machine, using GnuPG: import CA public key, create new user

*  Set up a gpg test environment and import the CA public key:

`$ mkdir /tmp/test/`

`$ export GNUPGHOME=/tmp/test/`

`$ gpg --import ca.pubkey`

*  create and export a keypair (and optionally a revocation certificate) for
 Alice:

`$ gpg --pinentry-mode=loopback --quick-generate-key alice@example.org`

`$ gpg --export --armor alice@example.org > alice.pubkey`

`$ gpg --gen-revoke alice@example.org > alice-revocation.asc`

Alternatively, if your `gpg` generated a revocation certificate automagically (usually in `$GNUPGHOME/openpgp-revocs.d/<key_fingerprint>.rev`), you can use that, but remember to edit the file and remove the "`:`" at the beginning of the "`BEGIN PGP PUBLIC KEY BLOCK`" line.

*  tsign the CA public key with this key:

`$ gpg --edit-key openpgp-ca@example.org`

enter `tsign`, `2`, `250`, no domain (so just hit `Enter`), `y`, `save`.

*  export the signed CA public key:

`$ gpg --export --armor openpgp-ca@example.org > ca-tsigned.pubkey`

## Part 3: OpenPGP CA admin imports the newly created user

*  copy the files `ca-tsigned.pubkey`, `alice.pubkey` and
 `alice-revocation.asc` so they are accessible for OpenPGP CA 

*  In OpenPGP CA, import Alice's key and revocation certificate - and Alice's
 trust signature on the CA key:

`$ openpgp-ca user import --name "Alice Adams" --email alice@example.org --key-file alice.pubkey --revocation-file alice-revocation.asc`

`$ openpgp-ca ca import-tsig --file ca-tsigned.pubkey`

*  Check OpenPGP CA's user list:

`$ openpgp-ca user list`

This should show that Alice's key has been signed by the CA and that Alice
 has made a trust signature on the CA public key  

*  Export Alice's public key (this includes the signature by the CA):

`$ openpgp-ca user export --email alice@example.org`
