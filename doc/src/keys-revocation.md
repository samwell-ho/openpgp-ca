# Dealing with revocations of user certificates in OpenPGP CA

There are various reasons why we might want to revoke a user's OpenPGP key.
The user's key might have been compromised, the user might have left our
organization, ....

OpenPGP CA optionally stores revocation certificates. For every user, there
may be one or many revocations available.

To check which revocation certificates exist for a given email, the OpenPGP
CA admin can query by email:

`$ openpgp-ca -d example.oca user show-revocations --email bob@example.org`

The results show a numeric "revocation id". These IDs identify specific
individual revocation certificates.

When we've determined which revocation certificate we want to apply, we can
 apply that revocation to the user's key:

`$ openpgp-ca -d example.oca user apply-revocation --id 2`

Afterwards, "show-revocations" will display the additional note: "this
revocation has been PUBLISHED", and the user's public key contains the
revocation certificate.

As this version of the user's key gets disseminated, the OpenPGP
implementations of third parties learn that the key should no longer be used.

The updated public key with the included revocation can be exported by running
 
`$ openpgp-ca -d example.oca user export --email 'bob@example.org'`
