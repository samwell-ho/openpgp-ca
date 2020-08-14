# OpenPGP certification authority

OpenPGP CA is a tool for managing OpenPGP keys within an organization.

The primary goal is to make it trivial for end users to authenticate
OpenPGP keys of other users in their organization (or in affiliated
organizations).

*Authentication* here means that users can be confident that they are using
the right OpenPGP key for their communication partners. 
 
The benefit that using OpenPGP CA brings is roughly the same as if each user
had verified and signed the keys of everyone they regularly communicate
with - but without the overhead of every user having to actually authenticate
and sign all of those keys manually.

The approach of OpenPGP CA moves the effort of authentication to a new role in
the organization: the *OpenPGP CA admin* sets up the web of trust for
all users, so that the users can be confident that they are using the right
OpenPGP keys for their communication partners.
This works without users needing training to perform these tasks - and without
each user needing to spend significant effort on authenticating a
potentially large number of keys. 


## Quick intro

When using OpenPGP CA's centralized key creation workflow, generating
new OpenPGP keys for users in your organization is
as simple as running the following commands (and distributing the resulting
key material to user machines):

```
$ openpgp-ca -d example.oca ca init example.org 

$ openpgp-ca -d example.oca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca -d example.oca user add --email bob@example.org --name "Bob Baker"
```

The first command generates a new key for the OpenPGP CA itself, the
following commands generate keys for two users. The private user keys are
output to stdout (and never stored locally) - these private keys need to be
stored (e.g. as `alice.priv` and `bob.priv`) and transferred to the respective
users. By default, these keys are protected by passphrases (which need to
be transmitted to Alice and Bob over a secure channel, for them to be able
to access their OpenPGP keys).

The users also need access to the OpenPGP CA's public key, which can be
manually exported as follows:

`$ openpgp-ca -d example.org ca export > example-ca.pub`

After this, users can import - for example using gnupg, as follows (for
testing purposes, a temporary gnupg environment is set up):

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
$ gpg --import alice.priv
$ gpg --import example-ca.pub
```

Finally, gnupg needs to be told that Alice considers the key `alice.priv`
as her own (and thus "trusted"):

`$ gpg --edit-key alice@example.org`

Then enter `trust`, `<enter>` `5`, `<enter>`, `y`, `<enter>`, `quit`,
`<enter>`.

Before setting this "trust", Alice needs to make sure that this key is
indeed the correct one for her - for example by having the OpenPGP CA admin
confirm the key's fingerprint on a sufficiently secure channel.

After this, users can automatically authenticate each other as soon as their
OpenPGP implementations have copies of other users' keys.
Users do not need to manually check fingerprints or sign each others' keys.

This means that, for example, Thunderbird/Enigmail will show green header
bars for received email from contacts that the OpenPGP CA admin has
authenticated.

E.g. when Alice gets email from Bob, there is visual confirmation in her
email software that the key that Bob used to sign his email has been
verified to actually be Bob's key by the OpenPGP CA admin.

## Documentation

For more details and more workflows (including a workflow to create user keys
on the user's machine, and then import those keys into OpenPGP CA) - see the
documentation at:

https://openpgp-ca.gitlab.io/openpgp-ca/
