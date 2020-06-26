This chapter shows some ways of inspecting data in the OpenPGP CA
 database 

### Inspecting and exporting keys

We can inspect the state of all users in OpenPGP CA like this:

`$ openpgp-ca -d example.oca user list`

Export an individual user key (the public key is
printed to stdout):

`$ openpgp-ca -d example.oca user export -e alice@example.org`

To output all public keys in OpenPGP CA to stdout:

`$ openpgp-ca -d example.oca user export`

To output the public key of the OpenPGP CA admin:

`$ openpgp-ca -d example.oca ca export`

### Checking certifications and expiry

To check if all keys are mutually certified (all user keys tsigned the
CA key, and the CA key has certified all user keys), and report the results:

`$ openpgp-ca -d example.oca user check sigs`
 
To check if any keys have expired and report the results:
 
`$ openpgp-ca -d example.oca user check expiry`

To check if any keys will expire within a specified number of days:
 
`$ openpgp-ca -d example.oca user check expiry --days 60`
