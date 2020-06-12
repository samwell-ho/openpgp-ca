# Export Certificates to a Web Key Directory (WKD)

OpenPGP CA can export Certificates in Web Key Directory (WKD) format
(https://tools.ietf.org/html/draft-koch-openpgp-webkey-service-08)

Set up a new OpenPGP CA instance and create two users: 

`$ export OPENPGP_CA_DB=/tmp/openpgp-ca.sqlite`

`$ openpgp-ca ca init example.org` 

`$ openpgp-ca user add --email alice@example.org --name "Alice Adams"`

`$ openpgp-ca user add --email bob@example.org --name "Bob Baker"`

Export keys into a WKD structure:

`$ openpgp-ca wkd export /tmp/wkd/`

Using/testing WKD as a client (to use WKD, the export needs to be on the
webserver for the relevant domain, in the correct directory, with https set
up):

`$ gpg --auto-key-locate clear,nodefault,wkd --locate-key openpgp-ca@example.org`

or

`$ sq wkd get openpgp-ca@example.org`

