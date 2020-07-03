Setting up an OpenPGP CA bridge means that users between organizations
are automatically mutually authenticated:

Any user at one organization sees the OpenPGP keys of users at the other
organization as verified and vice versa. The authentications that are
performed by the OpenPGP CA admins at each organization are effectively shared
between the two organizations.
Users can thus seamlessly authenticate users in both organizations.

A bridge is configured when the CA admins at both organizations are
satisfied that the other organization is following good
procedures in certifying keys of users in their organization.

In this chapter we set up two example organizations, `some.org` and
`other.org`.
Two independent instances of OpenPGP CA are set up, as well as users for each
organization (using the centralized OpenPGP CA workflow).
Then a "bridge" is configured between both OpenPGP CA instances.

## Part 1: Set up OpenPGP CA instance 1
 
Set up an OpenPGP CA instance for our first organization, `some.org` and
create a new user:

`$ openpgp-ca -d some.oca ca init some.org`

`$ openpgp-ca -d some.oca user add --email alice@some.org --name "Alice Adams"`

```
new user key for Alice Adams:
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: E24F 8B54 2DBD EA05 D7C5  66BB E40C 1185 0CD5 8EF5
Comment: Alice Adams <alice@some.org>

xYYEXv8wVRYJKwYBBAHaRw8BAQdAZvMwopKhFuQ2p7eDrqEHDriA97Ofh1oxBc4p
gJEv0/j+CQMIMzRSUoQBJpv/nqO4myMfH04y7heSyAtdZYW1Imh3dOCT4stlX1Kt
[...]
FiEE4k+LVC296gXXxWa75AwRhQzVjvVXAgEA4W2m0Mp2zph0vuXaBSqAdE3tl+UI
maKI1ruhnPW5KHEA/AodNGWjXf3SrN2HaUiuw5KrWtqfkzqh8P7pEuJEmsYB
=56dh
-----END PGP PRIVATE KEY BLOCK-----

password for this key: 'ambiguity Gap Fineness Surely denote'
```

We will need the public key of the OpenPGP CA to set up the bridge
from the second organization, so we export it:

`$ openpgp-ca -d some.oca ca export > some-ca.pub`

## Part 2: Set up OpenPGP CA instance 2

Set up an OpenPGP CA instance for our second organization, `other.org` and
create a new user:

`$ openpgp-ca -d other.oca ca init other.org`

`$ openpgp-ca -d other.oca user add --email bob@other.org --name "Bob Baker"`

```
new user key for Bob Baker:
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: AF99 A0F0 218F DA56 49E6  CC3C 89E6 8A01 93C8 6438
Comment: Bob Baker <bob@other.org>

xYYEXv8wjRYJKwYBBAHaRw8BAQdAur2CaodIcP1at8VddR9AGJty5z2oBA38ubEW
IAbO4OD+CQMIqY6BVv7v0OT/sOUZNMdRE215JQbMqOXM7G0ePyhaXuWxckI9Dvzz
[...]
r5mg8CGP2lZJ5sw8ieaKAZPIZDh2BwEAg8tP3SAO0joJCi3m195JUy/xAYoWldEy
eJSnbiuL30kBAODAli9L8gwGyX7WgPBG62Hre2PqxJvZt8cjscDBstIE
=1fqR
-----END PGP PRIVATE KEY BLOCK-----

password for this key: 'radar Undergrad consuming Repulsive Emptiness'
```

We will need the public key of the OpenPGP CA to set up the bridge
from the first organization, so we export it:

`$ openpgp-ca -d other.oca ca export > other-ca.pub`

## Part 3: OpenPGP CA instance 1 configures bridge
 
Now we are going to set up the bridge from the side of the first organization
 `some.org`.
Taking this step means that the OpenPGP CA admin at `some.org` trusts the
OpenPGP CA admin at the second organization, `other.org`, to correctly
authenticate users within their organization.

### Configure bridge to instance 2

Setting up this bridge means that CA 1 creates a trust signature for the
public key of the remote organization (in this case, `other.org`).
This trust signature is implicitly scoped to the domainname `other.org` by
OpenPGP CA.

`$ openpgp-ca -d some.oca bridge new --remote-key-file other-ca.pub`

OpenPGP CA prints a message showing the fingerprint of the remote key
that you just configured a bridge to. Please double-check that this
fingerprint really belongs to the intended remote CA admin before
disseminating the newly trust-signed public key!

```
signed certificate for openpgp-ca@other.org as bridge

CAUTION:
The fingerprint of the remote CA key is
0B8D 10E9 B64F BABC 51EC  545C BC3A 0B86 2EBC 829F

Please verify that this key is controlled by openpgp-ca@other.org before disseminating the signed remote certificate
```

### Export keys

For the bridge to take effect, the certification we just generated needs to
be published. To this end, we export our newly signed version of the public
key of CA 2 (other.org):

`$ openpgp-ca -d some.oca bridge list > other.signed`

Independently, we export the user keys at `some.org`, for testing, below.

`$ openpgp-ca -d some.oca user export > some.users`

## Part 4: OpenPGP CA instance 2 configures bridge

Analogous to the previous step, we now set up the bridge in the other
direction. The OpenPGP CA admin at `other.org` creates a certification for
the OpenPGP CA key of `some.org`.

CA 2 creates a trust signature for the public key of CA 1 (implicitly
scoped to the domainname "some.org") of the remote organization (again,
please make sure that the fingerprint belongs to the intended remote CA!)

`$ openpgp-ca -d other.oca bridge new --remote-key-file some-ca.pub`

```

signed certificate for openpgp-ca@some.org as bridge

CAUTION:
The fingerprint of the remote CA key is
B40B 4A74 45A4 2522 CE33  90C0 EF2C 4DD0 AD96 4FAF

Please verify that this key is controlled by openpgp-ca@some.org before disseminating the signed remote certificate
```

### Export keys

As above, we export the public key of CA 1 (some.org) that now includes
the certification we just created:

`$ openpgp-ca -d other.oca bridge list > some.signed`

We also export the user keys at `other.org`, for testing in the next step.

`$ openpgp-ca -d other.oca user export > other.users`

## Part 5: Import all keys into Alice's GnuPG environment, confirm authentication

Now we import all of the keys we exported above to see how the bridge will
look from a user's point of view. We're going to do this as `alice@some.org`.

### Setting up a GnuPG test environment 

For testing purposes, you'll want to create a separate test environment.
Using GnuPG, this can be done as follows:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
```

### Import user keys and CA keys of both organizations

`$ gpg --import some.signed other.signed some.users other.users`

```
gpg: keybox '/tmp/tmp.jRItGKnQZn/pubring.kbx' created
gpg: key EF2C4DD0AD964FAF: 2 signatures not checked due to missing keys
gpg: /tmp/tmp.jRItGKnQZn/trustdb.gpg: trustdb created
gpg: key EF2C4DD0AD964FAF: public key "OpenPGP CA <openpgp-ca@some.org>" imported
gpg: key BC3A0B862EBC829F: 2 signatures not checked due to missing keys
gpg: key BC3A0B862EBC829F: public key "OpenPGP CA <openpgp-ca@other.org>" imported
gpg: key E40C11850CD58EF5: public key "Alice Adams <alice@some.org>" imported
gpg: key 89E68A0193C86438: 1 signature not checked due to a missing key
gpg: key 89E68A0193C86438: public key "Bob Baker <bob@other.org>" imported
gpg: Total number processed: 4
gpg:               imported: 4
gpg: no ultimately trusted keys found
```

### Set ownertrust for Alice

Alice now marks her own key as "trusted", signifying that Alice considers
this key as her own:

`$ gpg --edit-key alice@some.org`

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
[ unknown] (1). Alice Adams <alice@some.org>

gpg> trust
pub  ed25519/E40C11850CD58EF5
     created: 2020-07-03  expires: never       usage: C
     trust: unknown       validity: unknown
sub  ed25519/3D28C93C0C8B6BAC
     created: 2020-07-03  expires: never       usage: S
sub  cv25519/574F0AAEA9316D6E
     created: 2020-07-03  expires: never       usage: E
[ unknown] (1). Alice Adams <alice@some.org>

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
[ unknown] (1). Alice Adams <alice@some.org>
Please note that the shown key validity is not necessarily correct
unless you restart the program.

gpg> quit
```

### Inspect authentication in Alice's GnuPG instance 

Now we can check what Alice (who works at `some.org`) sees in
her OpenPGP instance:

`$ gpg --list-keys`

GnuPG shows "ultimate" trust for Alice's own key (we configured that in the
previous step), and "full" trust for both OpenPGP CA keys, as well as
for Bob (who works at `other.org`):

So Alice at `some.org` now has an authenticated path to
Bob at `other.org` in the web of trust. Alice
will also automatically have authenticated paths to any other users that
will be set up at `other.org`.

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
uid           [  full  ] OpenPGP CA <openpgp-ca@some.org>
sub   ed25519 2020-07-03 [S]

pub   ed25519 2020-07-03 [C]
      0B8D10E9B64FBABC51EC545CBC3A0B862EBC829F
uid           [  full  ] OpenPGP CA <openpgp-ca@other.org>
sub   ed25519 2020-07-03 [S]

pub   ed25519 2020-07-03 [C]
      E24F8B542DBDEA05D7C566BBE40C11850CD58EF5
uid           [ultimate] Alice Adams <alice@some.org>
sub   ed25519 2020-07-03 [S]
sub   cv25519 2020-07-03 [E]

pub   ed25519 2020-07-03 [C]
      AF99A0F0218FDA5649E6CC3C89E68A0193C86438
uid           [  full  ] Bob Baker <bob@other.org>
sub   ed25519 2020-07-03 [S]
sub   cv25519 2020-07-03 [E]
```

# Variation on the bridging Workflow example:

In "Part 2", CA 2 creates an additional user outside of the domain `other.org`:

`$ openpgp-ca user add --email carol@third.org --name "Carol Cruz"`

The rest of the workflow is performed exactly as above.

Alice can still authenticate both OpenPGP CA keys, as well as
Bob. Carol however is (correctly) shown as not authenticated.

{add more context/explanation}
