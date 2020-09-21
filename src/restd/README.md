# Experimental REST API for OpenPGP CA

To use the OpenPGP CA as a REST service, the CA first needs to be initialized
once (to create the CA key):

```
$ openpgp-ca -d example.oca ca init example.org
```

Then the REST daemon can be started:

```
$ openpgp-ca-restd -d example.oca

🔧 Configured for development.
    => address: localhost
    => port: 8000
    => log: normal
    => workers: 8
    => secret key: generated
    => limits: forms = 32KiB
    => keep-alive: 5s
    => tls: disabled
🛰  Mounting /api:
    => POST /api/users/new application/json (post_user_new)
🚀 Rocket has launched from http://localhost:8000
```

To test this service, you can now add a new user via POST using curl:

```
curl --header "Content-Type: application/json" --request POST --data @user.json  http://localhost:8000/api/users/new
```

With a data-file `user.json` as follows:

```
{"email": ["alice@example.org"],
 "name": "Alice Adams",
 "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBF9orW8BEAC9RievEe67QyvqV7XGnGVV2VwMGuoJFtER8xwU0RCSqKMnu6L+
un0wri829zQm/trLebHDD70Dvwe6Wl5gwXJtbKTETMg3KuJ51DAZvo4W0JUkEvwC
[..]
iIJw33bSlyssaXTnnfGR5KySs91HCl8PlZHJBz4D6+Tae27cA14rcrgRewO8YyBZ
=vus6
-----END PGP PUBLIC KEY BLOCK-----"}
```
