# Export keys to a Web Key Directory (WKD)

OpenPGP CA can export keys in
[Web Key Directory (WKD)](https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08)
format.

## Initialize an OpenPGP CA instance with test users

If we have no OpenPGP CA instance at hand, we set up a fresh one and create
two users:

```
$ export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite
$ openpgp-ca ca init example.org
$ openpgp-ca user add --email alice@example.org --name "Alice Adams"
$ openpgp-ca user add --email bob@example.org --name "Bob Baker"
```

## Export keys into a WKD structure:

Now that we have an OpenPGP CA instance with two users, we can easily export
WKD data for our organization to the filesystem into the path `/tmp/wkd/`
like this:

`$ openpgp-ca wkd export /tmp/wkd/`

To use this data, you need to configure a web server to serve this data
from the correct domain. The directory structure on the web server must
conform to the WKD specification, and https must be set up.

## Testing WKD

When we've set up a WKD server, we can retrieve key from it using an OpenPGP client.

For example with GnuPG:

`$ gpg --auto-key-locate clear,nodefault,wkd --locate-key alice@example.org`

Or with Sequoia PGP:

`$ sq wkd get alice@example.org`
