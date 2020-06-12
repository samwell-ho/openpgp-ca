# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys of other users in their organization (or in affiliated
organizations).

This means that users get roughly the same benefits as if they had verified
and signed the keys of everyone they regularly communicate with, but
without the overhead of having to manually authenticate all of those keys. 


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


## Documentation

For more details and more workflows (including decentralized key
creation, if you prefer to create user keys on the user's machine) - see the
documentation:

https://openpgp-ca.gitlab.io/openpgp-ca/
