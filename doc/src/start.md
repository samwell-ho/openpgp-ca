# Usage

## Quick intro

When using OpenPGP CA's centralized key creation workflow, generating
new OpenPGP keys for users in your organization is
as simple as running the following commands (and distributing the resulting
key material to user machines):

```
$ export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite
$ openpgp-ca ca init example.org 

$ openpgp-ca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca user add --email bob@example.org --name "Bob Baker"
```

Users can automatically authenticate each other as soon as their OpenPGP
implementations have copies of the user keys and the OpenPGP CA admin's key.
Users do not need to manually check fingerprints or sign each others' keys.

