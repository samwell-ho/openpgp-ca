The second approach for managing user keys with OpenPGP CA is that users
create their own keys, and supply their public key to the OpenPGP CA admin.
We call this workflow "decentralized key creation", because OpenPGP keys do
not get created centrally, but decentrally, by each individual user.

Importing user generated keys into OpenPGP CA involves setting up
certifications between the CA key and the new user key.

This workflow gives users full control over their own keys. In
particular, the OpenPGP CA admin never has access to the user's private key
material.

However, this workflow is currently more complicated to perform
than centralized key creation.

## Part 1: Preparations on the OpenPGP CA side

### Setting up an OpenPGP CA instance

To start, if we don't already have an instance of OpenPGP CA, we need to set up a
new one. We initialize a new OpenPGP CA instance for the domain (in this case,
we'll use `example.org`) and generate a new keypair for the OpenPGP CA admin:

`$ openpgp-ca -d example.oca ca init example.org` 

By convention, the OpenPGP CA admin uses the email address `openpgp-ca@example.org`.
If possible, you should adhere to this convention so that it is easier for
users and software to discover the CA key for your organization.

### Export the OpenPGP CA's public key

Then we export the CA public key to the file `openpgp-ca.pub`,
for use on the user's machine:

`$ openpgp-ca -d example.oca ca export > openpgp-ca.pub`

## Part 2: Key creation on user's machine

On the user's machine, we're going to generate a new OpenPGP key.

We're using GnuPG in this example. Other OpenPGP software will have a similar
workflow, but details will differ.

### Setting up a GnuPG test environment

For testing purposes, we create a separate test environment.
Using GnuPG, this can be done as follows:

```
$ export GNUPGHOME=$(mktemp -d)
$ chmod 0700 $GNUPGHOME
```

### Create a new key for the user

We create a new key for Alice:

`$ gpg --quick-generate-key alice@example.org`

```
gpg: keybox '/tmp/tmp.LSAJszDQLR/pubring.kbx' created
About to create a key for:
    "alice@example.org"

Continue? (Y/n)
[...]
public and secret key created and signed.

pub   rsa3072 2020-07-02 [SC] [expires: 2022-07-02]
      A0A61C7554B3316009C8D3C74FBA1B7EF003F9FA
uid                      alice@example.org
sub   rsa3072 2020-07-02 [E]
```

Then we export the public part of this key into the file `alice.pub`:

`$ gpg --export --armor alice@example.org > alice.pub`

### Optionally generate revocation certificate(s) 

If we want the OpenPGP CA admin to be able to revoke Alice's key, then we need
to create revocation certificates. We can generate and store multiple
revocation certificates for different scenarios - the individual revocation
certificates will show different reasons why a revocation was performed.

We'll generate three variants here:  "Key has been compromised", "Key is
superseded" and "Key is no longer used".

`$ gpg --gen-revoke alice@example.org > alice-revocation-compromised.asc`

```
sec  rsa3072/4FBA1B7EF003F9FA 2020-07-02 alice@example.org

Create a revocation certificate for this key? (y/N) y
Please select the reason for the revocation:
  0 = No reason specified
  1 = Key has been compromised
  2 = Key is superseded
  3 = Key is no longer used
  Q = Cancel
(Probably you want to select 1 here)
Your decision? 1
Enter an optional description; end it with an empty line:
>
Reason for revocation: Key has been compromised
(No description given)
Is this okay? (y/N) y
ASCII armored output forced.
Revocation certificate created.
```

`$ gpg --gen-revoke alice@example.org > alice-revocation-superseded.asc`

As above, but using `2` when queried for the "reason" for revocation. 

`$ gpg --gen-revoke alice@example.org > alice-revocation-nolongerused.asc`

As above, but using `3` when queried for the "reason" for revocation.

These revocations cover the typical situations, but they all have the
current timestamp. When the user's key needs to be revoked in the future,
we can use the one that shows the appropriate reason. However, the time of
revocation will be shown as the time when the revocation certificates were
generated.

In the centralized key creation workflow, OpenPGP CA can generate and
store hundreds of revocation certificates, showing different revocation
times, so when a revocation of that user's key becomes necessary, the
OpenPGP CA admin can use the most suitable revocation certificate, both in
terms of the reason for revocation, as well as the time of revocation.

### Making the OpenPGP CA key a trusted introducer

Now, as the user, we're going to mark the OpenPGP CA key as trusted
introducer. This means that the user trusts the CA to authenticate keys on
their behalf (this is expected in OpenPGP CA).

First, we import the OpenPGP CA's public key:

`$ gpg --import openpgp-ca.pub`

```
gpg: key A29FE591ABEF048D: public key "OpenPGP CA <openpgp-ca@example.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Transporting the OpenPGP CA public key to the user doesn't require any
confidentiality. Any medium is fine (email, a USB key, ...).
However, the user must verify after import that the key has the expected
fingerprint:

```
$ gpg --fingerprint openpgp-ca@example.org
pub   ed25519 2020-07-02 [C]
      D3D2 EC7B 5C19 C304 3456  0A00 A29F E591 ABEF 048D
uid           [ unknown] OpenPGP CA <openpgp-ca@example.org>
sub   ed25519 2020-07-02 [S]
```

In this example, we imported a key with the fingerprint
`D3D2 EC7B 5C19 C304 3456  0A00 A29F E591 ABEF 048D`. This information needs
to be compared against a trustworthy source for that fingerprint. The user
might call their OpenPGP CA admin on the phone, or they might have received a
printout of the fingerprint in a trustworthy manner.

After comparing the complete fingerprint against a trusted source, we're
sure we have the correct key for OpenPGP CA. So we mark the
key as a trusted introducer. To do this, we create a trust signature:

`$ gpg --edit-key openpgp-ca@example.org`

Enter `tsign`, `2`, `250`, no domain (just hit `Enter`), `y`, `save`.

```
gpg (GnuPG) 2.2.12; Copyright (C) 2018 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


pub  ed25519/A29FE591ABEF048D
     created: 2020-07-02  expires: never       usage: C
     trust: unknown       validity: unknown
sub  ed25519/59C433434D284F57
     created: 2020-07-02  expires: never       usage: S
[ unknown] (1). OpenPGP CA <openpgp-ca@example.org>

gpg> tsign

pub  ed25519/A29FE591ABEF048D
     created: 2020-07-02  expires: never       usage: C
     trust: unknown       validity: unknown
 Primary key fingerprint: D3D2 EC7B 5C19 C304 3456  0A00 A29F E591 ABEF 048D

     OpenPGP CA <openpgp-ca@example.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I trust marginally
  2 = I trust fully

Your selection? 2

Please enter the depth of this trust signature.
A depth greater than 1 allows the key you are signing to make
trust signatures on your behalf.

Your selection? 250

Please enter a domain to restrict this signature, or enter for none.

Your selection?

Are you sure that you want to sign this key with your
key "alice@example.org" (4FBA1B7EF003F9FA)

Really sign? (y/N) y

gpg> save
```

### Export the CA's public key

The user now exports the OpenPGP CA key, which now contains the trust
signature:

`$ gpg --export --armor openpgp-ca@example.org > ca-tsigned.pub`


## Part 3: OpenPGP CA admin (import the newly created user key)

The user transfers `ca-tsigned.pub`, `alice.pub` - and optionally any
revocation certificates - to the CA admin. 

The CA admin then imports all of Alice's artifacts into the OpenPGP CA
database:

`$ openpgp-ca -d example.oca user import --name "Alice Adams" --email alice@example.org --key-file alice.pub --revocation-file alice-revocation-compromised.asc --revocation-file alice-revocation-superseded.asc --revocation-file alice-revocation-nolongerused.asc`

`$ openpgp-ca -d example.oca ca import-tsig ca-tsigned.pub`

### Export Alice's public key (including the signature by the CA)

When we imported Alice's public key, OpenPGP CA automatically signed the
key.  Now, we might want to export her key including that certification and
publish it somewhere, so that her key can be integrated into the WoT:

`$ openpgp-ca -d example.oca user export --email alice@example.org`

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: A0A6 1C75 54B3 3160 09C8  D3C7 4FBA 1B7E F003 F9FA
Comment: alice@example.org

xsDNBF7+RLIBDADBl0vzO2JHnFUbazounaSjWN/qKzHM964L3N/8q/B8ZNj19J5f
1eaRu15ssZQcf/nVIYxjX4ZbRQIhsSCCd+wBcBVoEV4/AsoIslfF2xxFDmWLg5Ve
[...]
qsLY89yDDmBOiMipsHEe+PLIRivmQhgIHfPb7AD4g3dbNiOUWsD7bhi4IR8Whz8P
Al1QBfoy5sLFO0rIlxsXGeJSw+rxRt9Wau4=
=9gNp
-----END PGP PUBLIC KEY BLOCK-----
```

In most cases, we will want to publish an updated wkd export of our OpenPGP
CA instance on our WKD server. This way, clients can automatically receive
Alice's key complete with the certification by OpenPGP CA.

### Check OpenPGP CA's user list

To see the resulting state in OpenPGP CA, we can inspect the `user list`:

`$ openpgp-ca -d example.oca user list`

```
usercert for 'Alice Adams'
fingerprint A0A61C7554B3316009C8D3C74FBA1B7EF003F9FA
user cert (or subkey) signed by CA: true
user cert has tsigned CA: true
- email alice@example.org
 expires: 02/07/2022
 3 revocation certificate(s) available
```

This should show that Alice's key has been signed by the CA and that Alice
has generated a trust signature over the CA public key  

The next chapter shows more examples of inspecting the contents of the
OpenPGP CA database.