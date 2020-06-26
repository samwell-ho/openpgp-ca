This example shows how the OpenPGP CA admin can import user-generated keys
into OpenPGP CA.

We call this workflow "decentralized key creation", because OpenPGP keys do
not get created centrally, but decentrally, by each individual user.

Importing user generated keys involves setting up certifications
between the CA admin key and the new user key.

This workflow gives users full control over their own keys. In
particular, the OpenPGP CA admin never has access to the user's secret key
material.

However, this workflow is currently more complicated to perform
than centralized key creation.

## Part 1: Preparations on the OpenPGP CA side

If we don't already have an instance of OpenPGP CA, we set up a new one:

`$ openpgp-ca -d example.oca ca init example.org` 

Then we export the CA public key to the file `openpgp-ca.pubkey`,
for use on the user's machine:

`$ openpgp-ca -d example.oca ca export > openpgp-ca.pubkey` 

## Part 2: Key creation on user's machine

On the user's machine, we're going to generate a new OpenPGP key.

We're using GnuPG in this example. Other OpenPGP software will have a similar
workflow, but details will differ.

### Setting up a GnuPG test environment

For testing purposes, you'll want to create a separate test environment.
Using GnuPG, this can be done as follows:

`$ mkdir /tmp/test/ && chmod 0700 /tmp/test`

`$ export GNUPGHOME=/tmp/test/`

### Create a new key for the user

We create a new key for Alice:

`$ gpg --pinentry-mode=loopback --quick-generate-key alice@example.org`

Then we export the public part of this key into the file `alice.pubkey`:

`$ gpg --export --armor alice@example.org > alice.pubkey`

### Optionally generate a revocation certificate 

If we want to keep a revocation certificate for this user key in OpenPGP CA,
we can generate one as follows:

`$ gpg --gen-revoke alice@example.org > alice-revocation.asc`

Alternatively, GnuPG might already have generated a revocation certificate
(usually stored in `$GNUPGHOME/openpgp-revocs.d/<key_fingerprint>.rev`). If
you want to use it, remember to edit the file and remove the "`:`" at the
beginning of the "`BEGIN PGP PUBLIC KEY BLOCK`" line.

### Delegate authentication to the CA public key

Now, as the user, we're going to mark the OpenPGP CA admin key as trusted
for the purpose of authentication (this is expected in OpenPGP CA).

First, we import the OpenPGP CA admin's public key:

`$ gpg --import openpgp-ca.pubkey`

(Transport / Checking fingerprint?)

Then we delegate authentication to the OpenPGP CA admin. To do this, we
create a trust signature:

`$ gpg --edit-key openpgp-ca@example.org`

Enter `tsign`, `2`, `250`, no domain (so just hit `Enter`), `y`, `save`.

### Export the CA public key

The user now exports the OpenPGP CA admin key, which now contains the trust
signature:

`$ gpg --export --armor openpgp-ca@example.org > ca-tsigned.pubkey`


## Part 3: OpenPGP CA admin (import the newly created user key)

The user transfers `ca-tsigned.pubkey`, `alice.pubkey` - and optionally the
revocation certificate - to the CA admin. 

The CA admin the imports all of Alice's artifacts into the OpenPGP CA
 database:

`$ openpgp-ca -d example.oca user import --name "Alice Adams" --email alice@example.org --key-file alice.pubkey --revocation-file alice-revocation.asc`

`$ openpgp-ca -d example.oca ca import-tsig --file ca-tsigned.pubkey`

### Export Alice's public key (this includes the signature by the CA)

Alice's public key has been certified by the OpenPGP CA admin key at this
point. We can export the key including this certification:

`$ openpgp-ca -d example.oca user export --email alice@example.org`

### Check OpenPGP CA's user list

To see the resulting state in OpenPGP CA, we can inspect the `user list`:

`$ openpgp-ca -d example.oca user list`

This should show that Alice's key has been signed by the CA and that Alice
has generated a trust signature over the CA public key  

The next chapter shows more examples of inspecting the contents of the
OpenPGP CA database.