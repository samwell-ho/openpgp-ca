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
    => GET /certs/by_email/<email> (certs_by_email)
    => GET /certs/by_fp/<fp> (certs_by_fp)
    => GET /certs/check application/json (check_cert)
    => POST /certs application/json (post_user)
    => POST /certs/deactivate/<fp> (deactivate_cert)
    => DELETE /certs/<fp> (delist_cert)
    => POST /refresh_ca_certifications (refresh_certifications)
    => POST /poll_updates (poll_for_updates)
🚀 Rocket has launched from http://localhost:8000
```

## Previewing an OpenPGP certificate (before adding or update)

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

mDMEX419BRYJKwYBBAHaRw8BAQdAnfJuV3EHFAJ31D968YvLlAAu0YqUxySSJ1Lh
ZeFRGhiIiQQfFgoAOwWCX419BQWJBaSPvQMLCQcJEGzJHRdUZDEGAxUKCAKbAQIe
ARYhBLcCUD+7JL2xZWJweGzJHRdUZDEGAABrPAD/byicPJZ8jy1ltwVMhm4YGADa
9SrxXioiT0ekwmb/+OoA/3wtR2erbbRS8z7+2eQ7qrCoRWk/FRKL6aDv7GKHS3EC
tBFhbGljZUBleGFtcGxlLm9yZ4iMBBMWCgA+BYJfjX0FBYkFpI+9AwsJBwkQbMkd
F1RkMQYDFQoIApkBApsBAh4BFiEEtwJQP7skvbFlYnB4bMkdF1RkMQYAANv8AP9G
MadAR2b3JOLvoe4b5MWwg0aVGY49rvVx39sU6OWFiwEAlLo9zCq8++ClBIuZDZcB
5WYHX/eTUzyyWUV3D2Zsowy4MwRfjX0FFgkrBgEEAdpHDwEBB0DpdKcbcCQRWnXw
75pBIF2jXWJk9Yp4oSK+87F4xfgCWoj4BBgWCgCqBYJfjX0FBYkFpI+9CRBsyR0X
VGQxBgKbAgIeAXagBBkWCgAnBYJfjX0FCRCgJ8lVXt8OxhYhBONIP93aDZThvL4K
aaAnyVVe3w7GAAAWYwD9FX3JULe0K6IfcpxhP6sKfjx20NdXLXueX5fg9/D6Bt0B
AOf5L4ACGZPCNwSG90dUtA9DiYbFlJTs80OKQ8YjETIMFiEEtwJQP7skvbFlYnB4
bMkdF1RkMQYAAPt0AQC/vVwTx4TUbo4ustT7wJ/9Q60e/Kns2AQ+tfKBsLldqgEA
8qibe9f7xjlTz6KfohB3dHkJRQh8I+90PWpT4wMK6Aa4OARfjX0FEgorBgEEAZdV
AQUBAQdAuObJBQI6kR3a0zslOKqs2Ojav/Ssgt9fmREBZ/EAXnQDAQgJiIEEGBYK
ADMFgl+NfQUFiQWkj70JEGzJHRdUZDEGApsMAh4BFiEEtwJQP7skvbFlYnB4bMkd
F1RkMQYAAPC0AQCA+xFqHX8503ijkIg4nQntnUzi7r5tdi2t2MMRFpf2SgEAtNLD
Xof5uIAoYhwfZWuSg3ggQv4/JaxXO02UIQx4pQk=
=GU5p
-----END PGP PUBLIC KEY BLOCK-----"}
```

The output of this call is JSON-formatted information about the certificate
(or an error, if the certificate is not acceptable to our system).

```
{
  "cert_info": {
    "fingerprint": "B702503FBB24BDB1656270786CC91D1754643106",
    "user_ids": [
      "alice@example.org"
    ],
    "primary_creation_time": "2020-10-19T11:48:21Z"
  },
  "action": "update",
  "certificate": {
    "email": [
      "alice@example.org"
    ],
    "name": "Alice Adams",
    "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106\nComment: alice@example.org\n\nxjMEX419BRYJKwYBBAHaRw8BAQdAnfJuV3EHFAJ31D968YvLlAAu0YqUxySSJ1Lh\nZeFRGhjCiQQfFgoAOwWCX419BQWJBaSPvQMLCQcJEGzJHRdUZDEGAxUKCAKbAQIe\nARYhBLcCUD+7JL2xZWJweGzJHRdUZDEGAABrPAD/byicPJZ8jy1ltwVMhm4YGADa\n9SrxXioiT0ekwmb/+OoA/3wtR2erbbRS8z7+2eQ7qrCoRWk/FRKL6aDv7GKHS3EC\nzRFhbGljZUBleGFtcGxlLm9yZ8KMBBMWCgA+BYJfjX0FBYkFpI+9AwsJBwkQbMkd\nF1RkMQYDFQoIApkBApsBAh4BFiEEtwJQP7skvbFlYnB4bMkdF1RkMQYAANv8AP9G\nMadAR2b3JOLvoe4b5MWwg0aVGY49rvVx39sU6OWFiwEAlLo9zCq8++ClBIuZDZcB\n5WYHX/eTUzyyWUV3D2ZsowzOMwRfjX0FFgkrBgEEAdpHDwEBB0DpdKcbcCQRWnXw\n75pBIF2jXWJk9Yp4oSK+87F4xfgCWsLAOAQYFgoAqgWCX419BQWJBaSPvQkQbMkd\nF1RkMQYCmwICHgF2oAQZFgoAJwWCX419BQkQoCfJVV7fDsYWIQTjSD/d2g2U4by+\nCmmgJ8lVXt8OxgAAFmMA/RV9yVC3tCuiH3KcYT+rCn48dtDXVy17nl+X4Pfw+gbd\nAQDn+S+AAhmTwjcEhvdHVLQPQ4mGxZSU7PNDikPGIxEyDBYhBLcCUD+7JL2xZWJw\neGzJHRdUZDEGAAD7dAEAv71cE8eE1G6OLrLU+8Cf/UOtHvyp7NgEPrXygbC5XaoB\nAPKom3vX+8Y5U8+in6IQd3R5CUUIfCPvdD1qU+MDCugGzjgEX419BRIKKwYBBAGX\nVQEFAQEHQLjmyQUCOpEd2tM7JTiqrNjo2r/0rILfX5kRAWfxAF50AwEICcKBBBgW\nCgAzBYJfjX0FBYkFpI+9CRBsyR0XVGQxBgKbDAIeARYhBLcCUD+7JL2xZWJweGzJ\nHRdUZDEGAADwtAEAgPsRah1/OdN4o5CIOJ0J7Z1M4u6+bXYtrdjDERaX9koBALTS\nw16H+biAKGIcH2VrkoN4IEL+PyWsVztNlCEMeKUJ\n=N/c9\n-----END PGP PUBLIC KEY BLOCK-----\n",
    "revocations": [],
    "delisted": null,
    "inactive": null
  }
}
```

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
curl --header "Content-Type: application/json" --request POST --data @user.json  http://localhost:8000/certs
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
curl --request GET http://localhost:8000/certs/by_email/alice@example.org
```

Among other information, the returned data contains fingerprint strings for
each certificate. These fingerprint strings are used as parameters for the
following operations.

The format of the returned data is the same as for `/certs/check`.

## Getting one OpenPGP certificate by fingerprint

To get one OpenPGP certificate by fingerprint, call:

```
curl --request GET http://localhost:8000/certs/by_fp/<fingerprint>
```

The format of the returned data is the same as for `/certs/check` and
`/certs/by_email`.

An example:

```
{
  "cert_info": {
    "fingerprint": "B702503FBB24BDB1656270786CC91D1754643106",
    "user_ids": [
      "alice@example.org"
    ]
    "primary_creation_time": "2020-10-19T11:48:21Z"
  },
  "action": null,
  "certificate": {
    "email": [
      "alice@example.org"
    ],
    "name": "Alice Adams",
    "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106\nComment: alice@example.org\n\nxjMEX419BRYJKwYBBAHaRw8BAQdAnfJuV3EHFAJ31D968YvLlAAu0YqUxySSJ1Lh\nZeFRGhjCiQQfFgoAOwWCX419BQWJBaSPvQMLCQcJEGzJHRdUZDEGAxUKCAKbAQIe\nARYhBLcCUD+7JL2xZWJweGzJHRdUZDEGAABrPAD/byicPJZ8jy1ltwVMhm4YGADa\n9SrxXioiT0ekwmb/+OoA/3wtR2erbbRS8z7+2eQ7qrCoRWk/FRKL6aDv7GKHS3EC\nzRFhbGljZUBleGFtcGxlLm9yZ8KMBBMWCgA+BYJfjX0FBYkFpI+9AwsJBwkQbMkd\nF1RkMQYDFQoIApkBApsBAh4BFiEEtwJQP7skvbFlYnB4bMkdF1RkMQYAANv8AP9G\nMadAR2b3JOLvoe4b5MWwg0aVGY49rvVx39sU6OWFiwEAlLo9zCq8++ClBIuZDZcB\n5WYHX/eTUzyyWUV3D2ZsowzCwXkEEAEKAC0Fgl+NgGsFgwHhM4AJEMbvFKdXSZcW\nFiEEH6Q6mn8dkeBce44Oxu8Up1dJlxYAAG2+EACKQkGtP7I+cD3uzFFY1/L+FCTw\nuC6YelD/spszA3Wf9vD5bs35H0G/EyrDVEi8AkZv2z4Ni99iW1QnR24qkrhwDn/i\nN6s9RLbGKmXhf5q+2Cc4Xo+n3sSDV6v3XCBA3d+GZK1c9Jpp3r0G7x5HcaaRi0uv\nEzu5uaqup9V5/4kEdJ2i69ueMhzFipEWjLMB3Lzbw/wlCWlzV/LkCHOYnMEXXREK\nSkSlAvte3lg8tTKAKC9Rjkm2VHfqU8Sxdqr+5h+UvM/Wxgz1uynNHrSI7soyQd8c\nFO+Z9QH70vRgvIcptlx7RiWOPWqWyC53rWsfbdlL/J/5kLnqtTNvc1gGzTBd1SZ2\nrdvWUTfnorkv1iSQ+v0mvXVe9O6z6rMWPId7vCa6LYAZvN5d5NiFgH+re0T6RVd5\nr7/fCE6nmXyL4itotRy9Y8h8U6k8TojNnIotPiCtDOEFrJMRzDJD+hu38/VLHK48\nQNXc1knYte0Se8KzMRD3t4+oSqGI1TpN9ZbRyFcLPQttXblgb/Tu4NuzJdThO110\njI0jeRfxvsdjzmBI8Ovw5fBO4JLCds4ZugHD9zIj2FZ2EWljajJVnSCrBh5XFNFT\nwUsBDIUuFaAzdS0dyQMuwAn+gro7FwojRp6WBnrft5ZLMBTDGCi3wCLjMsxk/+lj\nQ5mo+oAURR+6Un/eUc4zBF+NfQUWCSsGAQQB2kcPAQEHQOl0pxtwJBFadfDvmkEg\nXaNdYmT1inihIr7zsXjF+AJawsA4BBgWCgCqBYJfjX0FBYkFpI+9CRBsyR0XVGQx\nBgKbAgIeAXagBBkWCgAnBYJfjX0FCRCgJ8lVXt8OxhYhBONIP93aDZThvL4KaaAn\nyVVe3w7GAAAWYwD9FX3JULe0K6IfcpxhP6sKfjx20NdXLXueX5fg9/D6Bt0BAOf5\nL4ACGZPCNwSG90dUtA9DiYbFlJTs80OKQ8YjETIMFiEEtwJQP7skvbFlYnB4bMkd\nF1RkMQYAAPt0AQC/vVwTx4TUbo4ustT7wJ/9Q60e/Kns2AQ+tfKBsLldqgEA8qib\ne9f7xjlTz6KfohB3dHkJRQh8I+90PWpT4wMK6AbOOARfjX0FEgorBgEEAZdVAQUB\nAQdAuObJBQI6kR3a0zslOKqs2Ojav/Ssgt9fmREBZ/EAXnQDAQgJwoEEGBYKADMF\ngl+NfQUFiQWkj70JEGzJHRdUZDEGApsMAh4BFiEEtwJQP7skvbFlYnB4bMkdF1Rk\nMQYAAPC0AQCA+xFqHX8503ijkIg4nQntnUzi7r5tdi2t2MMRFpf2SgEAtNLDXof5\nuIAoYhwfZWuSg3ggQv4/JaxXO02UIQx4pQk=\n=o584\n-----END PGP PUBLIC KEY BLOCK-----\n",
    "revocations": [],
    "delisted": false,
    "inactive": false
  }
}
```

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
