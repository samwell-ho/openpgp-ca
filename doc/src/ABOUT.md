# 1. Overview

OpenPGP CA's primary goal is to make it trivial for end users to
authenticate OpenPGP keys for users in their organization or in an
adjacent organization.  Since people primarily communicate with people
in the same organization or one of a few related organizations, this
means that in the great majority of cases users in an OpenPGP CA-using
organization can authenticate their communication partners with no
effort on their part, and they will normally see a green icon, or
something similar, in their email client.  In other words, OpenPGP CA
makes it possible for users in an organization to securely and
seamlessly communicate via PGP-encrypted email using existing email
clients and encryption plugins without having to manually compare
fingerprints and without having to understand OpenPGP keys or
signatures.

OpenPGP CA achieves this goal by shifting the authentication burden to
an organization's administrator, and providing a tool that largely
automates key creation and signing as well as key dissemination.  And,
because OpenPGP CA works within the existing OpenPGP framework, users do
not need any new software to take advantage of OpenPGP CA's benefits.

One aspect of authenticating and using keys is making it easy to find
them.  For this, OpenPGP CA will optionally upload keys to key servers,
and/or maintain a WKD (the web/.well-known RFC).  In theory, OpenPGP CA
could also automate disseminating keys via technologies like DANE (DNS
records protected by the DNSSEC trust chain), and an LDAP-based
keystore, but in practice these are not widely deployed.  In other
words, these technologies (apart from "Keylist"---see more about Keylist
below) are orthogonal to the goals of OpenPGP CA.  None of them deals
with the creation and signing of key material. They are all mechanisms
for distributing key material.


# 2. Web of Trust Details (background and terminology)

OpenPGP provides a powerful mechanism to authenticate keys, the
so-called web of trust. The web of trust is built on certifications. A
certification is a machine-readable vouch, which asserts that an
identity controls a particular key. These certifications can be
exchanged between OpenPGP implementations and users, and are typically
included when distributing OpenPGP keys.

If Alice wants to determine whether Carol controls key 0xCCCC, then she
can use these vouches as evidence.  For instance, if Bob certified that
Carol controls key 0xCCCC, then his certification is evidence that Carol
controls key 0xCCCC.  Of course, Alice should only trust Bob's
certification as much as she trusts Bob to correctly certify Carol's
key.

OpenPGP certifications are extremely powerful.  For instance, Bob could
indicate that he not only believes that Carol controls key 0xCCCC, but
that he considers Carol to be a trusted introducer, i.e., a certificate
authority (CA).  In OpenPGP speak, this is done using a trust signature.

    https://tools.ietf.org/html/rfc4880#section-5.2.3.13

Trust signatures provide nuance.  For instance, it is possible to scope
the trust using regular expressions over the User ID.  For instance,
Carol may trust Dave from the NSA to certify users within his own
organization, but not other people.

    https://tools.ietf.org/html/rfc4880#section-5.2.3.14

These mechanisms are standard OpenPGP mechanisms, which all OpenPGP
implementations support.


# 3. OpenPGP CA: Benefits for users and administrators

## a) user perspective

   In OpenPGP CA, the CA administrator typically provisions users with a
key (although advanced users may bring their own key).  In addition to
generating a key, OpenPGP CA creates a number of signatures between the
new key and the CA's key.  Then, when the user imports their key into
their software, they find themselves in an OpenPGP setup where their
OpenPGP client can authenticate most of their communication partners
without any help---no comparing fingerprints, no key signing parties, no
understanding what a signature or certification is.

   This works, because the artifacts needed for authenticating keys
integrate with the tooling they are using: they are normal OpenPGP
artifacts.

   These benefits are---at least in theory---not particular to OpenPGP
CA: a dedicated administrator could perform the relevant tasks manually.
However, in practice, these tasks are so hard for administrators to
perform correctly with existing tooling that no one uses this type of
setup.


## b) admin perspective

   OpenPGP CA vastly improves the capabilities of the administrator by
giving them tooling to model *existing* trust relationships in their
organization.

   Right now, existing tooling in the OpenPGP ecosystem is mainly aimed
at users.  Dedicated administrators of OpenPGP setups have built ad-hoc
tools for tasks they perform, but these are point solutions, and often
incomplete.  OpenPGP CA is a general-purpose tool for both small and
large organizations.


# 4. Authentication in OpenPGP CA

Our approach to authentication is built using OpenPGP's "web of trust"
mechanisms.  Because these mechanisms are standard OpenPGP mechanisms,
all OpenPGP implementations understand them, and deploying OpenPGP CA
doesn't require modifying existing software or translating formats.

OpenPGP CA models trust in the following ways.

## a) authentication of individual user keys by the CA

In OpenPGP CA, the CA key signs the keys of all of the users in the
organization using normal OpenPGP certifications.

This is equivalent to "Keylist's" authenticated keylists, but is
natively understood by OpenPGP implementations.


## b) authentication between users within an organization

OpenPGP CA uses trust signatures to make it easy for users within an
organization to authenticate keys for other users in the same
organization: all users create a trust signature over their
organization's CA key.  (This is equivalent to marking the CA key as
fully trusted in GnuPG.)

## c) gateways into organizations

An added bonus of using a trust signature is that anyone who considers
someone at an OpenPGP CA-using organization to be a trusted introducer
can also automatically authenticate everyone else in the organization.
There is no equivalent to this in "Keylist".


## d) bridges between organizations

On top of that, OpenPGP CA will support creating "bridges" between
organizations: This concept is meant for cases where organizations
regularly work together, and the administrators of both organizations
feel that it's useful to mutually authenticate the users of their
respective organizations, in bulk.

OpenPGP CA bridges organizations using scoped trust signatures.  For
instance, if NLnet members and OTF members communicate with each other
on a regular basis, then the OpenPGP CA administrators can exchange
fingerprints, and create a scoped trust signature over each other's
domain.  Now, members of each organization can authenticate members of
the other organization.  This is also no equivalent to this in
"Keylist".

The reason that the signatures are scoped is that NLnet probably only
wants the OTF admin to be a trusted introducer for OTF members, and not
for any key, which would give a third-party too much power.