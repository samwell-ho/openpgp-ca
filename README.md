<!--
SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# OpenPGP CA

OpenPGP CA (certification authority) is a tool for managing OpenPGP 
keys in groups or organizations.

Imagine this:  Carol is the technical expert in her group.  The need for
protecting the group's communication has come up, and they are thinking
about how to improve this.
Carol knows about OpenPGP.  In fact, she's not only used OpenPGP herself,
she's helped out at a few crypto parties.  So, she knows: normal users,
even those who are worried about their security, have a very hard time
using OpenPGP securely; there are too many details for normal users to
worry about.

This is where OpenPGP CA helps.  The members of Carol's group trust her.
She is already their sysadmin.  So, it is sensible that Carol acts as a
certification authority (CA) for her group.  This is exactly what
OpenPGP CA helps Carol do.  Using OpenPGP CA, only Carol has to verify
fingerprints.  Then, her users just need to be taught to recognize whether
a message has been authenticated, and how to make sure 
encryption is enabled.  This significantly lowers the threshold to using
OpenPGP correctly, which gives Carol and her colleague a real chance of
communicating securely.


## Getting started

There are several ways to use OpenPGP CA.  Here, we show one
possible workflow.
Please read our [documentation](https://openpgp-ca.org/doc/) for more 
details.

The first thing that you need to do is to create an OpenPGP CA instance
for your organization:

```
$ openpgp-ca -d example.oca ca init example.org 
```

As part of this process, OpenPGP CA automatically creates a CA key for
your organization.  The key's User ID is set to `openpgp-ca@example.org`.
You should make sure that that email address is configured to forward
mail to you.


## Importing user keys

Once the CA is set up, users can supply their public keys to the CA admin
for use with OpenPGP CA.
 
We expect that most organizations will predominantly want to take this
approach: users will either want to use their pre-existing OpenPGP keys, or
generate new ones on their own machine.

For more details about this workflow, see
["importing user keys"](https://openpgp-ca.org/doc/keys-import/)
in our documentation. 


## Generating user keys with OpenPGP CA

Alternatively new user keys can be generated using OpenPGP CA.
This workflow is extremely simple to perform, so when it is appropriate for
keys to be centrally created, that is very easy to do with OpenPGP CA.

Let's generate two new keys:

```
$ openpgp-ca -d example.oca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca -d example.oca user add --email bob@example.org --name "Bob Baker"
```

The new private keys are printed to stdout (but they are never stored
locally!).
These private keys need to be transferred to the respective users. By
default, the keys are protected with passwords (which are also printed to
stdout on key creation).

One way to transport the keys is to store each on a USB key, and to write
each key's password and fingerprint on a piece of paper.

It is useful to give the new user the CA's public key at the same
time.  The CA key can be exported as follows:

```
$ openpgp-ca -d example.org ca export > example-ca.pub
```

Once the user has these keys (and the password), they can import them.
Using GnuPG, this is done as follows
 
For testing purposes, we first set up a temporary GnuPG environment:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
```

Then we import the new user key and the CA key:

```
$ gpg --import alice.priv
$ gpg --import example-ca.pub
```

Now, GnuPG needs to be told that Alice considers the key `alice.priv`
to be her own (and thus "ultimately trusted"):

```
$ gpg --edit-key alice@example.org
```

Then enter `trust`, `<enter>` `5`, `<enter>`, `y`, `<enter>`, `quit`,
`<enter>`.

Before setting this trust level, Alice needs to make sure that this key is
indeed the correct one for her - for example by having the OpenPGP CA admin
confirm the key's fingerprint on a sufficiently secure channel.

At this point, users in the organization (Alice and Bob, in our example) can
automatically authenticate each other as soon as their
OpenPGP implementations have copies of other users' keys;
Users do not need to manually check fingerprints or sign each others' keys.
OpenPGP CA also helps here: it can automatically generate a WKD.
This means that, for example, Thunderbird/Enigmail will show green header
bars for received email from contacts that the OpenPGP CA admin has
authenticated.  So when Alice gets email from Bob, there is visual
confirmation in her email software that the key that Bob used to sign his
email has been verified to actually be Bob's key.

OpenPGP CA makes it not only easy for users in an organization to
authenticate each other, but provides support to create so-called bridges
between organizations.  In this case, the CA admins from two OpenPGP CA
using organizations sign each others CA key using a scoped trust signature.


## Documentation

You might want to start by reading some more
[background information](https://openpgp-ca.org/background/)
information about OpenPGP CA, and then read about
[running an OpenPGP CA instance](https://openpgp-ca.org/doc/).

## Support

If you are interested in deploying OpenPGP CA in your organization, please
contact <heiko@schaefer.name> 
(OpenPGP 68C8B3725276BEBB3EEA0E208ACFC41124CCB82E).
We can consult, help you with your setup or even add features.

For non-profit organizations reduced rates are available.  This is also a
useful way for companies to support the project.
