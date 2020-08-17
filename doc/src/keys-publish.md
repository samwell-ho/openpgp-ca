<!--
SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

OpenPGP CA serves as a repository of user keys within our organization.
So when we want to publish OpenPGP keys for our organization, exporting
those keys from OpenPGP CA is a convenient possibility. 

There are several ways to publish keys:
- [Web Key Directory](https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-09) (WKD),
- [GPG Sync](https://github.com/firstlookmedia/gpgsync/)-style [Keylist](https://datatracker.ietf.org/doc/draft-mccain-keylist/),
- Key server (internal or [public](https://keys.openpgp.org/)),
- LDAP.

Of these, OpenPGP CA currently automates exporting as WKD.

# Publish keys as a WKD

## Initialize an OpenPGP CA instance with test users

If we have no OpenPGP CA instance at hand, we set up a fresh one and create
two users:

```
$ openpgp-ca -d example.oca ca init example.org
$ openpgp-ca -d example.oca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca -d example.oca user add --email bob@example.org --name "Bob Baker"
```

## Exporting a WKD

Now that we have an OpenPGP CA instance with two users, we can export the
WKD data for our organization to the filesystem into, say, `/tmp/wkd/`:

`$ openpgp-ca -d example.oca wkd export /tmp/wkd/`

To use this data as a WKD, you need to configure a web server to serve this
data from the correct domain. The directory structure on the web server must
conform to the WKD specification, and https must be set up.

## Transferring the WKD to a webserver

`/tmp/wkd` contains the full path as needed on the webserver (starting with `.well-known/openpgpkey`).

So you might copy it to your webserver as follows: 

`rsync --dry-run --recursive --delete /tmp/wkd/.well-known/openpgpkey/ www@example.org:public_html/.well-known/openpgpkey/`

We use `--delete` to delete stale data. To avoid accidentally deleting data, we've added the '--dry-run' option to the rsync command.
When you've checked that the output of this `rsync` run looks as expected, run
rsync again, but without the `--dry-run` parameter, to actually perform
the copy and delete operations.

## Testing WKD

When we've set up a WKD server, we can retrieve keys from it using an
OpenPGP client.

For example with GnuPG:

`$ gpg --auto-key-locate clear,nodefault,wkd --locate-key alice@example.org`

```
gpg: key 7B675240E4B0CCE7: public key "Alice Adams <alice@example.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: depth: 1  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 1f, 0u
gpg: depth: 2  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 1f, 0u
gpg: depth: 3  valid:   1  signed:   0  trust: 1-, 0q, 0n, 0m, 0f, 0u
pub   rsa3072 2020-07-03 [SC] [expires: 2022-07-03]
      23242C0704403804899C1B927B675240E4B0CCE7
uid           [ unknown] alice@example.org
sub   rsa3072 2020-07-03 [E]
```

Or with Sequoia PGP:

`$ sq wkd get alice@example.org`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 2324 2C07 0440 3804 899C  1B92 7B67 5240 E4B0 CCE7
Comment: Alice Adams <alice@example.org>

mQGNBF7/OtYBDADTHg2jy5IvDtjtC0mmnCYH4Bm8cHbPmHAdQJPCno9zZt27Hnap
AKKZY6/GtGwsSL3baAO7Q1R77ZKUsdsBb/zJk0JDdZZkyfOkdr29TyqF+fRD2SnH
[...]
EY6Q6JGTM5T360icl1dvBz+y5o2qaMRkGq/OURThdzQdONsfKyHbPEeB5cU1I+Hg
cir41OUw3syshyngRQNj/5WNpDVB756BZaHXr+4Wu69YLNzJ7DZdOp3qlupqok2w
Ay6X
=3yea
-----END PGP PUBLIC KEY BLOCK-----
```
