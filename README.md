<!--
SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# What is OpenPGP CA?

OpenPGP CA (certification authority) is a tool to handle OpenPGP keys in 
groups or organizations - it makes the OpenPGP experience of users easier 
and safer, at the same time.

Imagine this:  Carol is the technical expert in her group.  The need for
protecting the group's communication has come up, and they are thinking
about how to improve this.
Carol knows about OpenPGP.  In fact, she's not only used OpenPGP herself,
she's helped out at a few crypto parties.  So, she knows: normal users,
even those who are worried about their security, have a very hard time
using OpenPGP securely; there are too many details to worry about.

This is where OpenPGP CA helps.  The members of Carol's group trust her.
She is already their sysadmin.  So, it is sensible that Carol acts as a
certification authority (CA) for her group.  This is exactly what
OpenPGP CA helps Carol do.  Using OpenPGP CA, only Carol has to verify
fingerprints.  Her users need to be taught to recognize whether
a message has been authenticated, and how to make sure encryption is 
enabled. However, users don't need to validate the fingerprints of their 
communication partners, because the CA (operated by Carol) performs this 
task on their behalf. This significantly lowers the threshold to using 
OpenPGP correctly, which gives Carol and her colleagues a real chance of
communicating securely.


# Setting up your OpenPGP CA instance

OpenPGP CA is a flexible tool is designed to integrate usefully with a wide 
range of environments. There are many ways to make OpenPGP CA work for you.
Here, we show one typical workflow. Please read our
[documentation](https://openpgp-ca.org/doc/) for more details, or 
[talk to us](#get-in-touch-for-support) if you're unsure if OpenPGP CA is 
a good fit for your use case.


## Installing OpenPGP CA

To run an OpenPGP CA instance for your organization, first, you need to 
install the openpgp-ca tool on your machine.

Currently, you can either
[build OpenPGP CA on your machine](https://openpgp-ca.org/doc/start/),
run it as a [container image](https://openpgp-ca.org/doc/docker/) or 
deploy it to a [kubernetes cluster](https://openpgp-ca.org/doc/kubernetes/).


## Initializing your CA

Then you can create an OpenPGP CA instance for your organization:

```
$ openpgp-ca -d example.oca ca init example.org 
```

In this initialization step, OpenPGP CA creates an OpenPGP key for your CA.
The key's User ID is set to `openpgp-ca@example.org` (you should make sure
that that the CA email address is configured in your email setup to forward 
mail to you).

The parameter `-d <filename>` specifies where OpenPGP CA will store the 
information in CA. This includes the private OpenPGP key of your CA and the 
public keys of members of your organization. In this example, we'll use 
the file `example.oca` as storage for our CA's data.


## Manage user's keys in your CA

Once the CA is set up, users can supply their public keys to Carol, so she can
[keep track of the group's keys](https://openpgp-ca.org/doc/keys-import/)
in their OpenPGP CA instance.

Many users will have pre-existing OpenPGP keys that they'll want to keep 
using, others will make new ones on their own computer (possibly with 
Carol's guidance).

Alternatively, in some cases it can be appropriate to
[generate user keys centrally](https://openpgp-ca.org/doc/keys-create/),
using OpenPGP CA, but we won't cover this scenario, here.

Let's say Carol wants to import the public keys of her colleagues Alice and 
Bob in the CA. She obtains copies of their public keys and temporarily 
stores them in the files `alice.pub` and `bob.pub`.
Carol can obtain the public keys in any of a number of ways: Alice and Bob 
might have handed their keys to Carol on USB storage, sent them to 
Carol by email, or Carol might have pulled them from a public keyserver.

However, before proceeding, it's Carol's responsibility to verify the 
fingerprints of the keys. That is, she needs to make sure the fingerprints 
of the keys she has obtained match with the keys that Alice and Bob have 
on their machines. A typical approach is for Carol to meet Alice and Bob 
and read out and compare the fingerprints. Different organizations will 
follow different procedures. The main point is that Carol needs to 
make sure that she didn't obtain the wrong keys (either from a 
malicious third party - or by making a mistake, such as getting an old 
key for Bob from a keyserver, for which Bob has lost access to the 
private key material).

Once Carol has obtained and verified the keys, she can import them into 
the group's OpenPGP CA instance. The CA will certify user keys 
(based on Carol's verfication), and based on these certifications, 
everyone else in the organization can rely on getting the correct keys 
without having to personally verify every single one. Normally, users will 
only need to verify the CA's key.

To import the keys into the CA, Carol will perform the following steps:

```
openpgp-ca -d example.oca user import -e alice@example.org --key-file alice.pub
openpgp-ca -d example.oca user import -e bob@example.org -e bob.baker.39472384@gmail.com --key-file bob.pub
```

(Recall that `-d example.oca` specifies the location of your CA database, 
in this example workflow - in your setup, you could configure your CA 
database in your environment and omit this parameter)

Note that Carol explicitly provides email addresses for Alice and Bob's 
keys while importing them.

By specifying these email addresses, Carol instructs the OpenPGP CA 
instance to know which email addresses Carol considers to be appropriately 
associated with each key.
In this example, Carol instructs the CA to certify (using a digital 
signature) that the identity `alice@example.org` is correctly linked to 
the key in `alice.pub`.

Alice and Bob's keys may contain User IDs that Carol chooses not to 
certify with the CA. For example because those User IDs specify email 
addresses that are not relevant for the group's shared objectives. Or 
because Carol cannot verify those digital identities and thus opts not 
to certify them.


## Simplifying key discovery with WKD

OpenPGP CA can also significantly simplify key discovery: once you manage
the keys with OpenPGP CA, you can automatically output the keys to serve as a
[Web Key Directory (WKD)](https://openpgp-ca.org/doc/keys-publish/).

To publish your CA as a WKD, you can export all public keys for your 
domain, like this:

```
openpgp-ca -d example.oca wkd export /tmp/wkd/
```

When you serve the contents of this directory with a webserver under the 
hostname `openpgpkey.example.org` (note that you also need to configure 
https), your OpenPGP keys will be conveniently accessible to the general 
public. Most client software can retrieve keys from WKD, and will 
automatically find your WKD.

Note, however, that this approach only works for keys that have User IDs 
in your domain (`example.org`, here). Because WKD relies on the domain 
name system (DNS) for lookup, you cannot publish keys that only have User 
IDs that are external to your domain, via WKD.


# Users can rely on a CA for authentication

One major goal of OpenPGP CA is to make it simple for end users to use keys 
for their main communication partners with confidence - without having to 
manually verify each key. By relying on a CA, users delegate checking of 
keys to a party they explicitly trust.

When relying on a CA, users in the group instantly see each other's keys
as authenticated - as soon as their OpenPGP implementations obtain copies
of other users' keys, they can be certain that they have obtained the correct
key.

Users never need to manually check fingerprints of group members anymore (or
sign each others' keys). Instead, they rely on Carol performing the
verification task for them - and that Carol formalizes the resulting
knowledge as certifications by the group's CA.

This means that, for example, Thunderbird/Enigmail will show green header
bars for received email from contacts that the OpenPGP CA admin has
authenticated.  So when Alice gets email from Bob, there is visual
confirmation in her email software that the key that Bob used to sign his
email has been verified to actually be Bob's key.


## Relying on your CA with GnuPG

To take advantage of a CA, users need to obtain and verify the CA's key, and 
tell their OpenPGP software to
[rely on that CA](https://openpgp-ca.org/client/using_a_ca/). 
"Relying on a CA" means that users need to issue a trust signature for 
the CA key - by doing this, they instruct their OpenPGP software that 
they want to take advantage of certifications that the CA makes.

A user can configure their GnuPG installation to rely on a CA as follows. 
First, the user retrieves the CA's key via WKD, then they set up a *local 
trust signature (tlsign)* and make sure to verify the CA fingerprint they 
use is correct (they need to get the correct fingerprint from Carol - for 
example in printed form, or in a phone call):

```
$ gpg --locate-external-keys --auto-key-locate wkd openpgp-ca@example.org
$ gpg --edit-key '1234 5678 9ABC DEF0 1234  5678 9ABC DEF0 1234 5678'
gpg> tlsign
gpg> 2
gpg> 1
gpg> example.org
y
gpg> save
```

(The fingerprint *1234 5678 9ABC DEF0 1234  5678 9ABC DEF0 1234 5678* above 
needs to be replaced with the correct fingerprint for your CA's key)

By supplying `example.org` as a domain-restriction, we tell our GnuPG 
installation to only rely on the CA regarding certifications on identities 
in your domain `example.org` (depending on the nature of your organization 
it might be more appropriate to configure an unconstrained trust signature 
instead). 


## Testing authentication based on our CA

Anyone who has configured their OpenPGP environment to rely on our 
CA as shown above will automatically see our users' keys as "trusted": 

```
$ gpg --locate-external-keys --auto-key-locate wkd alice@example.org

[..]
uid           [  full  ] Alice <alice@example.org>
[..]
```


# Federation between organizations that use OpenPGP CA

OpenPGP CA not only makes it easy for users within an organization to
authenticate each other, but provides support to create so-called bridges
between organizations.  In this case, the CA admins from two OpenPGP CA
using organizations sign each others CA key using a scoped trust signature.

See the section on how bridges allow for authentication between organizations
[in our background documentation](https://openpgp-ca.org/background/details/)
for more details.

# Learn more

To get a deeper understanding of the ideas behind OpenPGP CA, you can read 
our documentation about the
[background and concepts](https://openpgp-ca.org/background/).

Or you can read our hands on documentation about how to
[run an OpenPGP CA instance](https://openpgp-ca.org/doc/).

End users can read our [client documentation](https://openpgp-ca.org/client/)
to learn how to take advantage of an existing CA.


# Get in touch for support

If you are interested in deploying OpenPGP CA in your organization, please
contact <heiko@schaefer.name> 
([68C8B3725276BEBB3EEA0E208ACFC41124CCB82E](https://openpgp-ca.org/heiko.asc)).
We can consult, help you with your setup, or even add features.

For non-profit organizations reduced rates are available.  This is also a
useful way for companies to support the project.
