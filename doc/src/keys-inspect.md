# Inspecting user certificates in OpenPGP CA

We can inspect the state of the users in OpenPGP CA like this:

`$ openpgp-ca user list`

Exporting an individual user certificate (the armorded certificate will be
printed on stdout):

`$ openpgp-ca user export -e alice@example.org`

To output all public certificates from OpenPGP:

`$ openpgp-ca user export`

To output the public certificate of the OpenPGP CA admin:

`$ openpgp-ca ca export`

OpenPGP CA can check if all keys are mutually signed (user keys tsigned the
 CA key, and the CA key has signed the user key), and report the results:
 
`$ openpgp-ca user check sigs`
 
OpenPGP CA can check if any keys have expired, and report the results:
 
`$ openpgp-ca user check expiry`

OpenPGP CA can also check if any keys have expired a specified number of
 days in the future and report the results:
 
`$ openpgp-ca user check expiry --days 60`
