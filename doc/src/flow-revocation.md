# Dealing with revocations of user certificates in OpenPGP CA

Check which revocation certificates exist for a given email.

`openpgp-ca user show-revocations --email bob@example.org`

The results show a numeric "revocation id".

Apply a revocation to the user's certificate:

`openpgp-ca user apply-revocation --id 2`

Afterwards, "show-revocations" will display the additional note: "this
revocation has been PUBLISHED", and the user's public key contains the
revocation certificate.

The updated public key can be displayed by running
 
`openpgp-ca user export --email 'bob@example.org'`
