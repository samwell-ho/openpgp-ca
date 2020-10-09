# Experimental REST API for OpenPGP CA

To use the OpenPGP CA as a REST service, first the CA needs to be
initialized once (to create the CA key):

```
$ openpgp-ca -d example.oca ca init example.org
```

Then the REST daemon can be started:

```
$ openpgp-ca-restd -d example.oca run

🔧 Configured for development.
    => address: localhost
    => port: 8000
    => log: normal
    => workers: 8
    => secret key: generated
    => limits: forms = 32KiB
    => keep-alive: 5s
    => tls: disabled
🛰  Mounting /:
    => GET /certs/list/<email> (list_certs)
    => GET /certs/check application/json (check_cert)
    => POST /certs application/json (post_user)
    => POST /certs/deactivate/<fp> (deactivate_cert)
    => DELETE /certs/<fp> (delist_cert)
    => POST /refresh_ca_certifications (refresh_certifications)
    => POST /poll_updates (poll_for_updates)
🚀 Rocket has launched from http://localhost:8000
```

## Previewing an OpenPGP certificate (addition or update)

When a user uploads an OpenPGP certificate (often referred to as a "key"),
it may either be new, or an update to a previous version of
the same key we already have.

In either case, our suggested workflow is to give the user feedback on
aspects of that key - and to then ask them if they want to persist this
data to OpenPGP CA.

It is useful to show human readable information about certificate additions
or updates for the user to review, because:

- OpenPGP certificates are typically not in a human-readable form, so it's
  useful to confirm that the user has actually uploaded the right key
- This REST-service potentially normalizes certificates,
  some data may be removed (e.g. some user_ids).
- In the case of an update to an existing certificate, information from
  both variants of the certificate will be merged.

```
curl --header "Content-Type: application/json" --request GET --data @user.json  http://localhost:8000/certs/check
```

The data-file `user.json` contains data in the form:

```
{"email": ["alice@example.org"],
 "name": "Alice Adams",
 "revocations": [],
 "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBF9orW8BEAC9RievEe67QyvqV7XGnGVV2VwMGuoJFtER8xwU0RCSqKMnu6L+
un0wri829zQm/trLebHDD70Dvwe6Wl5gwXJtbKTETMg3KuJ51DAZvo4W0JUkEvwC
[..]
iIJw33bSlyssaXTnnfGR5KySs91HCl8PlZHJBz4D6+Tae27cA14rcrgRewO8YyBZ
=vus6
-----END PGP PUBLIC KEY BLOCK-----"}
```

The output of this call is JSON-formatted information about the certificate
(or an error, if the certificate is not acceptable to our system).

Additionally, the result shows if the certificate is "new", or would be
handled as an update. 

This JSON data should be shown to the user, asking them if they want to
persist the certificate as shown. If they confirm, proceed to the next step to
persist the certificate.

## Persisting OpenPGP certificates

After previewing a certificate addition or update, and getting confirmation
for this data from the user, the data can be persisted to the OpenPGP CA
database via a POST request:

```
curl --header "Content-Type: application/json" --request POST --data @user.json  http://localhost:8000/users/new
```


## Revoking a certificate

When a user wants to stop using a certificate, normal procedure is that the
user applies a "revocation" to their certificate (the revocation marks the
certificate as invalid - and can contain additional information about the
 reason for revocation).
That updated version of the certificate is then published.

For the purpose of this API, this operation is a regular "update" to
the existing certificate.

This "update" (on the API level) has - in some sense - the semantics
of a "delete" operation (on the logical OpenPGP level):
The user's certificate was usable before the revocation - after the
operation it is marked as not usable.

However, after revocation, it is good practice to leave the (now invalidated)
certificate accessible on WKD (ideally indefinitely):
This is how third parties will learn of the key's revocation.


## Listing all OpenPGP certificates for a user

A user is identified by their email address, in this service.

Users may have multiple certificates in the OpenPGP CA database. For example:

- Past certificates that have been revoked (but that are still listed, so that
  third parties may learn of the revocations)
- A certificate that is still valid, but in the process of being phased out
- A new certificate that is in the process of replacing the previous one
- Additional special purpose certificates (such as a certificate for code
  signing) that the user wants to manage separately from their other
  OpenPGP certificates

To get a list of all OpenPGP certificates for a user, call:

```
curl --request GET http://localhost:8000/certs/list/alice@example.org
```

Among other information, the returned data contains fingerprint strings for
each certificate. These fingerprint strings are used as parameters for the
following operations.

(The format of the returned data is the same as for `/certs/check`)


## Marking a certificate as "deactivated"

When a user leaves an organization (such as EXAMPLE.ORG), this has subtle
implications for their OpenPGP certificate:

First of all, it probably doesn't mean that the certificate should be revoked.
A certificate can be associated with various email addresses (these
associations are represented as user_ids in OpenPGP certificates).
The user may keep using the certificate in other contexts, associated with
other email addresses.

When a user leaves EXAMPLE.ORG, it makes sense that EXAMPLE.ORG stops to
certify their user_id at EXAMPLE.ORG, such as `alice@example.org` (after
all, this email address does not exist anymore).

This is what we mean by "deactivation":
While a user has an email address at EXAMPLE.ORG, the EXAMPLE.ORG OpenPGP
CA instance will certify their user_id `alice@example.org`.
After the user  has left EXAMPLE.ORG, this certification will not be
renewed. EXAMPLE.ORG stops to certify that the OpenPGP certificate is
associated with the email address `alice@example.org`

However, it is also good practice to keep this key published on the WKD,
in this case. 

This "deactivate" operation can be performed like this:

```
curl --request POST http://localhost:8000/certs/deactivate/<fingerprint>
```

## De-listing a certificate

It is possible that a certificate should actually not be listed on the WKD any
more. However, this case is expected to be very rare.
When this operation is appropriate, it can be performed as follows:

```
curl --request DELETE http://localhost:8000/certs/<fingerprint>
```
