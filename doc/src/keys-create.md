There are two ways to manage user keys with OpenPGP CA.
The simplest way for both the admin and users is to have OpenPGP CA create
keys on behalf of the user.  This allows OpenPGP CA to automatically create
all of the necessary auxiliary data structures (the certifications and
revocation certificates).

We call this workflow "centralized key creation", because
OpenPGP keys get created centrally by the OpenPGP CA admin.

The disadvantage to this approach is that OpenPGP CA has access to the
user's private key material.  Although OpenPGP CA does not store it to
disk (it is only printed to stdout), the fact that the admin had access to the
keys is a potential security concern.  If this is a problem for you, then
the [next chapter](keys-import.md) describes how to import user-created keys
into OpenPGP CA.

## Part 1: Tasks on the OpenPGP CA admin machine

### Setting up an OpenPGP CA instance

To start, if we don't already have an instance of OpenPGP CA, we need to set up a
new one.

Then, we initialize a new OpenPGP CA instance for the domain (in this case,
we'll use `example.org`) and generate a new key for OpenPGP CA:

`$ openpgp-ca -d example.oca ca init example.org` 

By convention, the OpenPGP CA admin uses the email address `openpgp-ca@example.org`.
If possible, you should adhere to this convention so that it is easier for
users and software to discover the CA key for your organization.

### Creating a new user

To create a new user, you'll need their name and email address.  The
name is optional.

`$ openpgp-ca -d example.oca user add --email alice@example.org --name "Alice Adams"`

This creates a new OpenPGP key for the user, and the necessary
auxiliary data structure (in particular the mutual certifications),
and updates the database.

The new user's private key is sent to `stdout` by this command; it is not
stored. By default, the new key is protected with a diceware password,
which is also sent to `stdout`.

So the output of creating a new user looks like this:

```
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: 1C22 D485 B8C4 241C D857  6630 E118 78E5 2A41 C491
Comment: Alice Adams <alice@example.org>

xYYEXuyshhYJKwYBBAHaRw8BAQdAwsfLCGYg6lWqWM+4BuTy2wNpnLEhvvLiJLL5
[...]
feQnksqX3SRInBSvbCYBAMV3XC2AJX9mXuG4GWNw7z+FsfOI/knVggHTADuMerkK
=rI68
-----END PGP PRIVATE KEY BLOCK-----

password for this key: 'Unshackle empower mangy Habitual buddhism'
```

It is up to the admin to transfer the key to the user.  This can, for
example, be done by email or using a USB drive.

It doesn't hurt to keep the key encrypted while in transit, but it is not
essential, as the key is protected with a strong password. Safely getting
this password to the user, however, is crucial. The admin needs to devise a
secure method to communicate the password to the user.

The user then needs to import it into their OpenPGP keystore.  In the
following examples, we assume that the password-protected private key has been
transferred as a file called `alice.priv`.

### Exporting the OpenPGP CA public key

Alice also needs a copy of the CA's public key.  It can be exported as
follows:

`$ openpgp-ca -d example.oca ca export > ca.pub` 

The CA's key has already been tsigned by Alice's key.  This happened
automatically when OpenPGP CA generated the key.

## Part 2: Tasks on user's machine

The user needs to import the key on their machine.  In the following,
we assume that the user is using GnuPG.  Other software will have a
similar workflow, but the details will differ.

Alice needs to do two things: she needs to import her private key, and
the CA's public key.

### Setting up a GnuPG test environment

For testing purposes, we create a separate test environment.
Using GnuPG, this can be done as follows:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
```

### Importing Alice's private key

Alice needs to import the key and tell GnuPG that it is really her key.
In GnuPG, this is done by setting the so-called `ownertrust` to `Ultimate`.

Importing the key:

`$ gpg --import alice.priv`

The user needs to enter the diceware password of the key at this point.
This password needs to be transferred to the user through a sufficiently
secure channel (not by unencrypted email, or similar).

To set the `ownertrust`, you need to edit the key and then navigate the
text menus.  The menus are intended to be understood by programs, so the
structure doesn't change, and the following recipe should always work:

`$ gpg --edit-key alice@example.org`

Enter `trust`, `<enter>` `5`, `<enter>`, `y`, `<enter>`, `quit`, `<enter>`.

Now running `gpg -K alice@example.org` should show that the key is
ultimately trusted:

```
gpg -K alice@example.org
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
sec   ed25519 2020-06-19 [C]
      1C22D485B8C4241CD8576630E11878E52A41C491
uid           [ultimate] Alice Adams <alice@example.org>
ssb   ed25519 2020-06-19 [S]
ssb   cv25519 2020-06-19 [E]
```

### Importing the CA's public key

To import the CA's public key, run the following:

`$ gpg --import ca.pub`

Because Alice tsigned the CA's key, it should be shown as fully trusted.
You can confirm this by running:

```
$ gpg -k openpgp-ca@example.org
pub   ed25519 2020-06-19 [C]
      18D1788BA4B7C7519EDF09E5126A225FE174B7EC
uid           [  full  ] OpenPGP CA <openpgp-ca@example.org>
sub   ed25519 2020-06-19 [S]
```
