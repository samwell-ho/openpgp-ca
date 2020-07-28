Until now, we've shown how to use OpenPGP CA to make it easy for
users (or rather, their software) in the same organization to authenticate
each other's keys.  It is also possible for OpenPGP CA admins to connect their
organizations so that any user at one organization can authenticate the OpenPGP keys of users at the other
organization and vice versa.  This is done by creating a so-called
bridge between the two OpenPGP CA instances.

A bridge should only be created when the CA admins at both organizations are
satisfied that the other admin is following good
procedures in certifying keys of users in their organization.

In this chapter we set up two example organizations with OpenPGP CA,
`alpha.org` and `beta.org`, as well as users for each
organization.
Then a "bridge" is configured between the two OpenPGP CA instances.


## Part 1: Setting up an OpenPGP CA instance for alpha.org
 
We start by setting up an OpenPGP CA instance for our first organization, `alpha.org` and
creating a new user, Alice:

`$ openpgp-ca -d alpha.oca ca init alpha.org`

`$ openpgp-ca -d alpha.oca user add --email alice@alpha.org --name "Alice Adams"`

```
new user key for Alice Adams:
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: E24F 8B54 2DBD EA05 D7C5  66BB E40C 1185 0CD5 8EF5
Comment: Alice Adams <alice@alpha.org>

xYYEXv8wVRYJKwYBBAHaRw8BAQdAZvMwopKhFuQ2p7eDrqEHDriA97Ofh1oxBc4p
gJEv0/j+CQMIMzRSUoQBJpv/nqO4myMfH04y7heSyAtdZYW1Imh3dOCT4stlX1Kt
[...]
FiEE4k+LVC296gXXxWa75AwRhQzVjvVXAgEA4W2m0Mp2zph0vuXaBSqAdE3tl+UI
maKI1ruhnPW5KHEA/AodNGWjXf3SrN2HaUiuw5KrWtqfkzqh8P7pEuJEmsYB
=56dh
-----END PGP PRIVATE KEY BLOCK-----

password for this key: 'ambiguity Gap Fineness Surely denote'
```

The admin at `beta.org` will need the public key of the OpenPGP CA
instance to set up the bridge to `alpha.org`, so we export it:

`$ openpgp-ca -d alpha.oca ca export > alpha-ca.pub`

## Part 2: Setting up OpenPGP CA instance for beta.org

Then we set up an OpenPGP CA instance for our second organization,
`beta.org` and create a new user, Bob:

`$ openpgp-ca -d beta.oca ca init beta.org`

`$ openpgp-ca -d beta.oca user add --email bob@beta.org --name "Bob Baker"`

```
new user key for Bob Baker:
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: AF99 A0F0 218F DA56 49E6  CC3C 89E6 8A01 93C8 6438
Comment: Bob Baker <bob@beta.org>

xYYEXv8wjRYJKwYBBAHaRw8BAQdAur2CaodIcP1at8VddR9AGJty5z2oBA38ubEW
IAbO4OD+CQMIqY6BVv7v0OT/sOUZNMdRE215JQbMqOXM7G0ePyhaXuWxckI9Dvzz
[...]
r5mg8CGP2lZJ5sw8ieaKAZPIZDh2BwEAg8tP3SAO0joJCi3m195JUy/xAYoWldEy
eJSnbiuL30kBAODAli9L8gwGyX7WgPBG62Hre2PqxJvZt8cjscDBstIE
=1fqR
-----END PGP PRIVATE KEY BLOCK-----

password for this key: 'radar Undergrad consuming Repulsive Emptiness'
```

We will also need the public key of this OpenPGP CA instance so that the admin
at `alpha.org` can set up a bridge to `beta.org`, so we export it:

`$ openpgp-ca -d beta.oca ca export > beta-ca.pub`

## Part 3: OpenPGP CA admin at alpha.org configures bridge
  
Now we are going to set up the bridge from the side of `alpha.org`.
Taking this step means that the OpenPGP CA admin at `alpha.org` trusts the
OpenPGP CA admin at `beta.org` to correctly authenticate users within their
organization.

### Configuring a bridge to beta.org

To set up the bridge, the OpenPGP CA admin at `alpha.org` has obtained a
copy of the public key for `openpgp-ca@beta.org`.

First, the admin performs a dry run of "bridge new" (the default
behavior of "bridge new" is to only output information about the bridge,
without persisting anything to the database).

The purpose of this step is to check that we are using the correct key for
the remote OpenPGP CA instance.

```
$ openpgp-ca -d alpha.oca bridge new beta-ca.pub
Bridge creation DRY RUN.
 
Please verify that this is the correct fingerprint for the remote CA admin before continuing:
 
User ID: OpenPGP CA <openpgp-ca@beta.org>
Fingerprint '0B8D 10E9 B64F BABC 51EC  545C BC3A 0B86 2EBC 829F'
 
When you've confirmed that the remote key is correct, repeat this command with the additional parameter '--commit' to commit the OpenPGP CA bridge to the database.
```

Please double-check that this fingerprint really corresponds to the intended
remote CA admin before continuing!

When we're sure that the key in the file `beta-ca.pub` is the right one, we
proceed to actually configure the bridge and persist it in our OpenPGP CA
database:

`$ openpgp-ca -d alpha.oca bridge new beta-ca.pub --commit`

OpenPGP CA again prints a message showing the fingerprint of the remote key
that we just configured a bridge to.

```
signed certificate for openpgp-ca@beta.org as bridge

The fingerprint of the remote CA key is
0B8D 10E9 B64F BABC 51EC  545C BC3A 0B86 2EBC 829F
```

When the admin at `alpha.org` tells their OpenPGP CA instance to create a
bridge with `beta.org`, OpenPGP CA generates a trust signature for
`beta.org`'s OpenPGP CA key.
This trust signature is automatically scoped to the domainname `beta.org` by
OpenPGP CA.

For this trust signature to take effect, we need to publish it.

### Export/publish certification for the remote CA key

For users in `alpha.org` (or rather, their software) to be able to
authenticate users in `beta.org`, they need access to the certification on
the remote CA's key that we just created.  The best
way to distribute it is to publish it in a location for which the OpenPGP
software of users in `alpha.org` is configured to look for key updates.
 
In this tutorial, we transfer keys and certifications to clients manually,
using files. While this approach is possible to use in production, it is
tedious and there's a high risk that some users will end up with stale
versions of keys, because updates don't get rolled out to them.

Mechanisms that allow for automated updating of keys and
certifications by clients include:

1. [Keylist](https://code.firstlook.media/keylist-rfc-explainer)
2. [WKD](https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-09)

Keylist allows for local distribution of key material (including
certifications) of users outside one's organization. WKD, on the other hand
can only be used to distribute keys within the DNS domain of one's own
organization. In this case, the CA admin at `beta.org` could upload a
new copy of the OpenPGP CA public key on `beta.org`'s WKD instance that
includes the bridging trust signature by us.

For the purpose of this tutorial, we export our newly signed version of the
public key of OpenPGP CA at `beta.org` into a file:

`$ openpgp-ca -d alpha.oca bridge export openpgp-ca@beta.org > beta.signed`

To automatically receive updates such as this additional signature on the
`beta.org` OpenPGP CA key, users should ideally have a mechanism
that keeps their keyrings up-to-date.
This could be [GPG Sync](https://github.com/firstlookmedia/gpgsync/), or 
[parcimonie](https://packages.debian.org/de/sid/parcimonie), or
anything similar. 


## Part 4: OpenPGP CA admin at beta.org configures bridge

Now we are going to set up the bridge from the side of `beta.org`.
Taking this step means that the OpenPGP CA admin at `beta.org` trusts the
OpenPGP CA admin at `alpha.org` to correctly authenticate users within
their organization.

### Configuring a bridge to alpha.org

Analogous to the previous step, the OpenPGP CA admin first makes sure that
they have the correct key for the remote CA by performing a "bridge new" dry
run:

```
$ openpgp-ca -d beta.oca bridge new alpha-ca.pub
Bridge creation DRY RUN.

Please verify that this is the correct fingerprint for the remote CA admin before continuing:

User ID: OpenPGP CA <openpgp-ca@alpha.org>
Fingerprint 'B40B 4A74 45A4 2522 CE33  90C0 EF2C 4DD0 AD96 4FAF'

When you've confirmed that the remote key is correct, repeat this command with the additional parameter '--commit' to commit the OpenPGP CA bridge to the database.
```

After making sure the key is correct, the CA admin at `beta.org` now
sets up the bridge:

`$ openpgp-ca -d beta.oca bridge new alpha-ca.pub --commit`

```
signed certificate for openpgp-ca@alpha.org as bridge

The fingerprint of the remote CA key is
B40B 4A74 45A4 2522 CE33  90C0 EF2C 4DD0 AD96 4FAF
```

### Export/publish certification for the remote CA key

As above, we export the public key of the CA at `alpha.org` that now includes
the certification we just created:

`$ openpgp-ca -d beta.oca bridge export openpgp-ca@alpha.org > alpha.signed`

As above, this key - including our newly created certification - now needs
to be published, e.g. on a WKD server at `alpha.org` - or using Keylist.

## Part 5: Import all keys into Alice's GnuPG environment, confirm authentication

Now we import all of the keys we exported above to see how the bridge will
look from a user's point of view. We do this from `alice@alpha.org`'s perspectice.

### Setting up a GnuPG test environment 

For testing purposes, we create a separate test environment.
Using GnuPG, this can be done as follows:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
```

### Getting user keys from both OpenPGP CA instances

For the purpose of this tutorial, we export the public keys of users from both
OpenPGP CA instances into files, and make those files available to the user.

To export the user keys at `alpha.org`, we run

`$ openpgp-ca -d alpha.oca user export > alpha.users`

Likewise, to export the user keys at `beta.org`

`$ openpgp-ca -d beta.oca user export > beta.users`

In a real world scenario, those keys should instead be published on the
respective organizations' WKD server and retrieved by users' OpenPGP
software from there.


### Import user keys and CA keys of both organizations

`$ gpg --import alpha.signed beta.signed alpha.users beta.users`

```
gpg: keybox '/tmp/tmp.jRItGKnQZn/pubring.kbx' created
gpg: key EF2C4DD0AD964FAF: 2 signatures not checked due to missing keys
gpg: /tmp/tmp.jRItGKnQZn/trustdb.gpg: trustdb created
gpg: key EF2C4DD0AD964FAF: public key "OpenPGP CA <openpgp-ca@alpha.org>" imported
gpg: key BC3A0B862EBC829F: 2 signatures not checked due to missing keys
gpg: key BC3A0B862EBC829F: public key "OpenPGP CA <openpgp-ca@beta.org>" imported
gpg: key E40C11850CD58EF5: public key "Alice Adams <alice@alpha.org>" imported
gpg: key 89E68A0193C86438: 1 signature not checked due to a missing key
gpg: key 89E68A0193C86438: public key "Bob Baker <bob@beta.org>" imported
gpg: Total number processed: 4
gpg:               imported: 4
gpg: no ultimately trusted keys found
```

### Set ownertrust for Alice

Alice now marks her own key as "trusted", signifying that Alice considers
this key as her own:

`$ gpg --edit-key alice@alpha.org`

Then `trust`, `5`, `y`, `quit`.

```
gpg (GnuPG) 2.2.12; Copyright (C) 2018 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


pub  ed25519/E40C11850CD58EF5
     created: 2020-07-03  expires: never       usage: C
     trust: unknown       validity: unknown
sub  ed25519/3D28C93C0C8B6BAC
     created: 2020-07-03  expires: never       usage: S
sub  cv25519/574F0AAEA9316D6E
     created: 2020-07-03  expires: never       usage: E
[ unknown] (1). Alice Adams <alice@alpha.org>

gpg> trust
pub  ed25519/E40C11850CD58EF5
     created: 2020-07-03  expires: never       usage: C
     trust: unknown       validity: unknown
sub  ed25519/3D28C93C0C8B6BAC
     created: 2020-07-03  expires: never       usage: S
sub  cv25519/574F0AAEA9316D6E
     created: 2020-07-03  expires: never       usage: E
[ unknown] (1). Alice Adams <alice@alpha.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

pub  ed25519/E40C11850CD58EF5
     created: 2020-07-03  expires: never       usage: C
     trust: ultimate      validity: unknown
sub  ed25519/3D28C93C0C8B6BAC
     created: 2020-07-03  expires: never       usage: S
sub  cv25519/574F0AAEA9316D6E
     created: 2020-07-03  expires: never       usage: E
[ unknown] (1). Alice Adams <alice@alpha.org>
Please note that the shown key validity is not necessarily correct
unless you restart the program.

gpg> quit
```

### Inspect authentication information from Alice's perspectice

Now we can check what Alice (who works at `alpha.org`) sees in
her OpenPGP instance:

`$ gpg --list-keys`

GnuPG shows "ultimate" trust for Alice's own key (we configured that in the
previous step), and "full" trust for both OpenPGP CA keys, as well as
for Bob (who works at `beta.org`):

So Alice at `alpha.org` now has an authenticated path to
Bob at `beta.org` in the web of trust. Alice
will also automatically have authenticated paths to any other users that
will be set up at `beta.org` with OpenPGP CA.

```
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: depth: 1  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 1f, 0u
gpg: depth: 2  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 1f, 0u
gpg: depth: 3  valid:   1  signed:   0  trust: 1-, 0q, 0n, 0m, 0f, 0u
/tmp/tmp.jRItGKnQZn/pubring.kbx
-------------------------------
pub   ed25519 2020-07-03 [C]
      B40B4A7445A42522CE3390C0EF2C4DD0AD964FAF
uid           [  full  ] OpenPGP CA <openpgp-ca@alpha.org>
sub   ed25519 2020-07-03 [S]

pub   ed25519 2020-07-03 [C]
      0B8D10E9B64FBABC51EC545CBC3A0B862EBC829F
uid           [  full  ] OpenPGP CA <openpgp-ca@beta.org>
sub   ed25519 2020-07-03 [S]

pub   ed25519 2020-07-03 [C]
      E24F8B542DBDEA05D7C566BBE40C11850CD58EF5
uid           [ultimate] Alice Adams <alice@alpha.org>
sub   ed25519 2020-07-03 [S]
sub   cv25519 2020-07-03 [E]

pub   ed25519 2020-07-03 [C]
      AF99A0F0218FDA5649E6CC3C89E68A0193C86438
uid           [  full  ] Bob Baker <bob@beta.org>
sub   ed25519 2020-07-03 [S]
sub   cv25519 2020-07-03 [E]
```

# Variation on the bridging Workflow example, external Users

In "Part 2", the CA at `beta.org` creates an additional user outside of the domain `beta.org`:

`$ openpgp-ca user add --email carol@gamma.org --name "Carol Cruz"`

In other words, the CA at `beta.org` creates a key and certifies its user id
`carol@gamma.org`.
Note that Carol's user id is external to the CA's organization `beta.org`; 
her user id is at `gamma.org`. Such a setup is common
and it can be very useful for users at `beta.org` to have this direct
authenticated path to `carol@gamma.org`, who might be a common collaborator
for them. It's normal and expected that for internal use, an OpenPGP CA admin
may certify keys that are external to their organization.

The rest of the workflow is performed exactly as above.

Upon importing all keys into Alice's GnuPG environment,
Alice can still authenticate both OpenPGP CA keys, as well as
Bob. Carol however is (correctly) shown as not authenticated.

The technical reason for this absence of authentication from Alice's point
of view is that the bridge from `alpha.org` to `beta.org` is automatically
scoped to the domain `beta.org`.
 
In practice, this means that users at `alpha.org` only
rely on certifications that the OpenPGP CA at `beta.org` makes for users
within their own organization.

This approach makes the trust relationship between the two
organizations easier to reason about - we don't have to consider the
OpenPGP CA admin of a remote organization to be non-malicious in a
broad sense. Setting up a bridge only means that we trust the remote CA
admin to correctly certify users within their own organization (we don't
have to worry about the remote admin creating certifications for external
parties that our users should not trust).

Assume we set up a bridge to a hypothetical remote OpenPGP CA instance at
`nsa.gov`. It might be desirable for us, say, as a human rights
organization, to have an authenticated path to employees at NSA.
However, in this case, we do not want our users to consider certifications
that the CA admin at `nsa.gov` made for arbitrary users at other
organizations (even though such certifications might be valid and useful
within their own organization, for their internal use).

Scoping trust to remote organizations in this way formalizes the distinction
between certifications within an organization and certifications of keys
that are external to the organization. 
