# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys for users in their organization or in adjacent organizations.

## Quick intro

When using OpenPGP CA's centralized key creation workflow, generating mutually
authenticated OpenPGP keys for users in your organization is as simple as
running the following commands:

```
export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite
openpgp-ca ca init example.org 

openpgp-ca user add --email alice@example.org --name "Alice Adams"
openpgp-ca user add --email bob@example.org --name "Bob Baker"
```

At first we configure the sqlite database that all of OpenPGP CA's state
will be stored in (all persisted data of OpenPGP CA lives inside this single
file).

The `ca init` call creates an OpenPGP Key for the CA Admin. This
Key is stored in OpenPGP CA.

After that we call `user add` to create OpenPGP Keys for our two users, Alice
and Bob.
The private key material for those users is printed to stdout (the admin
needs to take appropriate steps to get those keys to the users' machines).

Those users can then automatically authenticate each other, as soon as the
users' OpenPGP implementations have copies of the user keys and the OpenPGP
CA admin's key. 

For more details and more workflows - including decentralized key
generation, if you prefer to create user keys on the user's machine - see the
documentation below.


## Documentation

https://openpgp-ca.gitlab.io/openpgp-ca/
