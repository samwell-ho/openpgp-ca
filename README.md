<!--
SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# OpenPGP CA

OpenPGP CA (certificate authority) is a tool for managing OpenPGP keys
within groups.

Imagine this:  Alice is the technical expert in her group.  The need for
protecting the group's communication has come up and they are thinking
about how to improve this.
Alice knows about OpenPGP.  In fact, she's not only used OpenPGP herself,
she's helped out at a few crypto parties.  So, she knows: normal users,
even those who are worried about their security, have a very hard time
using OpenPGP securely; there are too many details for normal users to
worry about.

This is where OpenPGP CA helps.  The members of Alice's group trust her.
She is already their sys admin.  So, it is sensible that Alice acts as a
kind of certificate authority (CA) for her group.  This is exactly what
OpenPGP CA helps Alice do.  Using OpenPGP CA, only Alice has to verify
fingerprints.  Then, her users just need to be taught to recognize whether
a message has been authenticated, and how to make sure 
encryption is enabled.  This significantly lowers the threshold to using
OpenPGP correctly, which gives Alice and her collegues a real chance of
communicating securely.


## Getting started

There are several different ways to use OpenPGP CA.  Here, we show one
possible workflow.
Please read [the book](https://openpgp-ca.gitlab.io/openpgp-ca/) for more
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

Next, we'll create a few users:

```
$ openpgp-ca -d example.oca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca -d example.oca user add --email bob@example.org --name "Bob Baker"
```

The private keys are output to stdout (but they are never stored locally!) -
these private keys need to be transferred to the respective users. By
default, the keys are protected by passphrases.
One way to do this is to store each key on a USB key, and to write each
key's passphrase and fingerprint on a piece of paper.

It is also convenient to give the new user the CA's public key at the same
time.  This can be exported as follows:

```
$ openpgp-ca -d example.org ca export > example-ca.pub
```

After this, users can import their new key.  Using GnuPG (and for
testing purposes, using a temporary gnupg environment), this is done as
follows:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
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

After this, users can automatically authenticate each other as soon as their
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

For more details and more workflows (including a workflow to create user keys
on the user's machine, and then import those keys into OpenPGP CA) - see the
documentation at:

https://openpgp-ca.gitlab.io/openpgp-ca/
