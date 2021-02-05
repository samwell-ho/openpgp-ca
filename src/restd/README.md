<!--
SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

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

## Previewing OpenPGP certificates (before adding or update)

When a user uploads OpenPGP certificates (often referred to as "PGP keys"),
each certificate may either be new, or an update to a previous version of
the same certificate we already have.

In either case, our suggested workflow is to give the user feedback on
aspects of each certificate - and to then ask them if they want to persist 
this data to OpenPGP CA.

It is useful to show human-readable information about certificate additions
or updates for the user to review, because:

- OpenPGP certificates are typically not in a human-readable form, so it's
  useful to confirm that the user has actually uploaded the right certificate
- This REST-service potentially normalizes certificates,
  some data may be removed (e.g. some user_ids).
- In the case of an update to an existing certificate, information from
  both variants of the certificate will be merged.

```
curl --header "Content-Type: application/json" --request GET --data @user.json  http://localhost:8000/certs/check
```

The payload (here we use a data-file `user.json`) contains data in the form:

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

Note: the "PGP PUBLIC KEY BLOCK" may be a "keyring" that actually contains 
multiple certificates. If so, each certificate will be individually 
checked - and the returned JSON will show if the certificate can be 
persisted or not. Additionally, there is a recommendation if the 
certificate *should* be uploaded, or the information that a certificate 
*can* or *cannot* be uploaded.


The output of this call is JSON-formatted information about the certificate
(or an error, if the certificate is not acceptable to our system).

```
[
  {
    "certificate": {
      "email": [
        "alice@example.org"
      ],
      "name": "Alice Adams",
      "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106\nComment: alice@example.org\n\nxjMEX419BRYJKwYBBAHaRw8BAQdAnfJuV3EHFAJ31D968YvLlAAu0YqUxySSJ1Lh\nZeFRGhjCiQQfFgoAOwWCX419BQWJBaSPvQMLCQcJEGzJHRdUZDEGAxUKCAKbAQIe\nARYhBLcCUD+7JL2xZWJweGzJHRdUZDEGAABrPAD/byicPJZ8jy1ltwVMhm4YGADa\n9SrxXioiT0ekwmb/+OoA/3wtR2erbbRS8z7+2eQ7qrCoRWk/FRKL6aDv7GKHS3EC\nzRFhbGljZUBleGFtcGxlLm9yZ8KMBBMWCgA+BYJfjX0FBYkFpI+9AwsJBwkQbMkd\nF1RkMQYDFQoIApkBApsBAh4BFiEEtwJQP7skvbFlYnB4bMkdF1RkMQYAANv8AP9G\nMadAR2b3JOLvoe4b5MWwg0aVGY49rvVx39sU6OWFiwEAlLo9zCq8++ClBIuZDZcB\n5WYHX/eTUzyyWUV3D2ZsowzOMwRfjX0FFgkrBgEEAdpHDwEBB0DpdKcbcCQRWnXw\n75pBIF2jXWJk9Yp4oSK+87F4xfgCWsLAOAQYFgoAqgWCX419BQWJBaSPvQkQbMkd\nF1RkMQYCmwICHgF2oAQZFgoAJwWCX419BQkQoCfJVV7fDsYWIQTjSD/d2g2U4by+\nCmmgJ8lVXt8OxgAAFmMA/RV9yVC3tCuiH3KcYT+rCn48dtDXVy17nl+X4Pfw+gbd\nAQDn+S+AAhmTwjcEhvdHVLQPQ4mGxZSU7PNDikPGIxEyDBYhBLcCUD+7JL2xZWJw\neGzJHRdUZDEGAAD7dAEAv71cE8eE1G6OLrLU+8Cf/UOtHvyp7NgEPrXygbC5XaoB\nAPKom3vX+8Y5U8+in6IQd3R5CUUIfCPvdD1qU+MDCugGzjgEX419BRIKKwYBBAGX\nVQEFAQEHQLjmyQUCOpEd2tM7JTiqrNjo2r/0rILfX5kRAWfxAF50AwEICcKBBBgW\nCgAzBYJfjX0FBYkFpI+9CRBsyR0XVGQxBgKbDAIeARYhBLcCUD+7JL2xZWJweGzJ\nHRdUZDEGAADwtAEAgPsRah1/OdN4o5CIOJ0J7Z1M4u6+bXYtrdjDERaX9koBALTS\nw16H+biAKGIcH2VrkoN4IEL+PyWsVztNlCEMeKUJ\n=N/c9\n-----END PGP PUBLIC KEY BLOCK-----\n",
      "revocations": [],
      "delisted": null,
      "inactive": null
    },
    "cert_info": {
      "user_ids": [
        {
          "email": "alice@example.org",
          "name": null,
          "raw": "alice@example.org"
        }
      ],
      "primary": {
        "fingerprint": "B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106",
        "flags": "C",
        "creation_time": "2020-10-19T11:48:21Z",
        "expiration_time": "2023-10-20T05:14:42Z",
        "algo": "EdDSA Edwards-curve Digital Signature Algorithm",
        "bits": 256
      },
      "subkeys": [
        {
          "fingerprint": "E348 3FDD DA0D 94E1 BCBE  0A69 A027 C955 5EDF 0EC6",
          "flags": "S",
          "creation_time": "2020-10-19T11:48:21Z",
          "expiration_time": "2023-10-20T05:14:42Z",
          "algo": "EdDSA Edwards-curve Digital Signature Algorithm",
          "bits": 256
        },
        {
          "fingerprint": "15C8 FAF9 7DE1 2426 263A  A81C E4B5 0215 FA66 80D5",
          "flags": "EtEr",
          "creation_time": "2020-10-19T11:48:21Z",
          "expiration_time": "2023-10-20T05:14:42Z",
          "algo": "ECDH public key algorithm",
          "bits": 256
        }
      ]
    },
    "action": "New",
    "upload": "Possible"
  }
]
```

The top level of the JSON format is split into two main parts:

- "certificate" shows an uninterpreted view of data in the OpenPGP CA database

- "cert_info" gives human readable details of the actual OpenPGP certificate. 
 This data is meant to be shown to users to help them determine if a 
 certificate they uploaded is indeed the one they intended to upload - or 
 to choose a subset out of a set of certificates, if they have uploaded 
 multiple certificates. 

Additionally, the result shows if the certificate is "new", or if it would be
handled as an "update" to an existing version of this certificate (i.e. we 
already have a version of the certificate with this fingerprint in OpenPGP 
CA). 

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

The call returns the same JSON format as the `/certs/check` call described 
above.

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
This is how third parties will learn of the certificate's revocation.


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

To get a list of all OpenPGP certificates for an email address, call:

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

The fingerprint parameter may be provided with or without 
spaces between hex blocks.

The format of the returned data is the same as for `/certs/check` and
`/certs/by_email`, however, `by_fp` returns at most one certificate.

An example:

```
{
  "certificate": {
    "email": [
      "alice@example.org"
    ],
    "name": "Alice Adams",
    "cert": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106\nComment: alice@example.org\n\n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\npQk=\n=OCvg\n-----END PGP PUBLIC KEY BLOCK-----\n",
    "revocations": [],
    "delisted": false,
    "inactive": false
  },
  "cert_info": {
    "user_ids": [
      {
        "email": "alice@example.org",
        "name": null,
        "raw": "alice@example.org"
      }
    ],
    "primary": {
      "fingerprint": "B702 503F BB24 BDB1 6562  7078 6CC9 1D17 5464 3106",
      "flags": "C",
      "creation_time": "2020-10-19T11:48:21Z",
      "expiration_time": "2023-10-20T05:14:42Z",
      "algo": "EdDSA Edwards-curve Digital Signature Algorithm",
      "bits": 256
    },
    "subkeys": [
      {
        "fingerprint": "E348 3FDD DA0D 94E1 BCBE  0A69 A027 C955 5EDF 0EC6",
        "flags": "S",
        "creation_time": "2020-10-19T11:48:21Z",
        "expiration_time": "2023-10-20T05:14:42Z",
        "algo": "EdDSA Edwards-curve Digital Signature Algorithm",
        "bits": 256
      },
      {
        "fingerprint": "15C8 FAF9 7DE1 2426 263A  A81C E4B5 0215 FA66 80D5",
        "flags": "EtEr",
        "creation_time": "2020-10-19T11:48:21Z",
        "expiration_time": "2023-10-20T05:14:42Z",
        "algo": "ECDH public key algorithm",
        "bits": 256
      }
    ]
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

However, it is good practice to keep this certificate published on the WKD,
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

## Checking for certificates that will expire soon

To check which certificates will expire in the next n days, the following 
endpoint returns a list of CertInfo.

Certs that are already expired or otherwise invalid at the time of the call 
are not reported.

```
curl --request GET http://localhost:8000/certs/expire/<days>
```
