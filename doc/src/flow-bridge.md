# Workflow: Bridging of two OpenPGP CA instances

This workflow builds on the "centralized key creation" workflow from above.

Two independent instances of OpenPGP CA are set up, users are created in each
instance. Then a "bridge" is configured between both OpenPGP CA instances.

Such a bridge is configured when the CA Admins at both organizations are
satisfied that the CA Admin of the other organization is following good
procedures in signing keys of users within their organization.

The end result is that users can seamlessly authenticate users in the
other organization, and vice versa.

## (1) OpenPGP CA instance 1 (setup CA and create a user)

set up CA, create a user

`export OPENPGP_CA_DB=/tmp/openpgp-ca1.sqlite`

`openpgp-ca ca init some.org`

`openpgp-ca user add --email alice@some.org --name "Alice Adams"`

export public PGP Certificate of OpenPGP CA admin:

`openpgp-ca ca export > ca1.pub`

## (2) OpenPGP CA instance 2 (setup CA and create a user)

`export OPENPGP_CA_DB=/tmp/openpgp-ca2.sqlite`

`openpgp-ca ca init other.org`

`openpgp-ca user add --email bob@other.org --name "Bob Baker"`

export public PGP Certificate of OpenPGP CA admin:

`openpgp-ca ca export > ca2.pub`

## (3) OpenPGP CA instance 1 (configure bridge to instance 2, export keys)

`export OPENPGP_CA_DB=/tmp/openpgp-ca1.sqlite`

CA 1 creates a trust signature for the public key of CA 2 (implicitly
scoped to the domainname "other.org") of the remote organization

`openpgp-ca bridge new --remote-key-file ca2.pub`

OpenPGP CA prints a message showing the fingerprint of the remote key
that you just configured a bridge to. Please double-check that this
fingerprint really belongs to the intended remote CA before disseminating
the newly trust-signed public key!

Export signed public key of CA 2:

`openpgp-ca bridge list > ca2.signed`

Export user keys

`openpgp-ca user export > ca1.users`

## (4) OpenPGP CA instance 2 (configure bridge to instance 1, export keys)

`export OPENPGP_CA_DB=/tmp/openpgp-ca2.sqlite`

CA 2 creates a trust signature for the public key of CA 1 (implicitly
scoped to the domainname "some.org") of the remote organization (again,
please make sure that the fingerprint belongs to the intended remote CA!)

`openpgp-ca bridge new --remote-key-file ca1.pub`

Export signed public key of CA 1:

`openpgp-ca bridge list > ca1.signed`

Export user keys

`openpgp-ca user export > ca2.users`

## (5) Import all keys into "Alice" gnupg test environment, confirm authentication

`mkdir /tmp/test/ && export GNUPGHOME=/tmp/test/`

`gpg --import  ca1.signed  ca2.signed ca1.users ca2.users`

Set ownertrust for Alice:

`gpg --edit-key alice@some.org`

Then `trust`, `5`, `quit`.

The resulting situation is what Alice (who works at "some.org") would see in
her OpenPGP instance:

gpg shows "ultimate" trust for Alice's own key, and "full" trust for
both OpenPGP CA Admin keys, as well as Bob (who works at "other.org"):

`gpg --list-keys`

# Variation on the bridging Workflow example:

In step (2), CA 2 creates an additional user outside of the domain "other.org":

`openpgp-ca user add --email carol@third.org --name "Carol Cruz"`

The rest of the workflow is performed exactly as above.

Alice can still authenticate both OpenPGP CA admin Certificates, as well as
Bob. Carol however is (correctly) shown as not authenticated.
