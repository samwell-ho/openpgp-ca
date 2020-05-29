# OpenPGP CA simplifies good OpenPGP practices in organizations/groups 

This is a high level overview of OpenPGP CA.
For technical details see the [next chapter](details.md).

## Terminology primer

This project deals with email encryption using OpenPGP.

Definitions/links for some terms:

PGP, OpenPGP, GnuPG, ... ?


## What is OpenPGP CA?

OpenPGP CA is:

1. A paradigm ("best practices") for how to use OpenPGP in organizations
   or groups with the central goal of improving security while
   simplifying and systematizing usage of OpenPGP

2. Tooling to easily apply this paradigm in practice:
   the tooling is particularly geared towards helping with tasks around
   managing OpenPGP keys and certifications (certification of keys is also
   referred to as "signing keys")

## Context

Anecdotal evidence suggests that OpenPGP is introduced to
organizations or groups as follows:

A technically competent person in the organization or group recognizes
the need for secure communication, convinces everyone to adopt
OpenPGP, and then holds a briefing/CryptoParty to teach everyone how to
generate a key, how to do key discovery, how to certify keys, etc.
When done well, the members of the organization understand what they need
to do to communicate securely.  But, even in the best cases, they often
only understand at a superficial level, and the technical leader needs to
provide intense support for most users.  And, authentication is often
neglected, due to the high overhead, and the perception that
"usually we will find the correct key in some kind of ad-hoc manner, anyway."

## What is authentication and why is it important?

One overarching goal of OpenPGP CA is that end users can be certain
they are using the correct OpenPGP keys for their {most common} communication
partners.

This is what
[authentication](https://en.wikipedia.org/wiki/Authentication)
means: ascertaining that an OpenPGP key we are using is indeed the correct
key for that other party.

From a user-perspective, when authentication works, they will normally just
see a green icon in their email client, or something similar.
This signals that they are using a cryptographic key that has been certified
to be the correct one.

More precisely, what we authenticate is an identity that a key claims (in
OpenPGP, this will often be an email-address such as `alice@example.org`).
Authentication deals with identifiers (such as an email address) and
verifies that the key in question is indeed controlled by the identity it
claims.

We then call a key "authenticated": the identity it claims has been
verified.

If we want to be sure that the identity a key claims is correct, we need a
mechanism to "authenticate" that key. The traditional method to
authenticate a key with OpenPGP is to manually check the fingerprint of
that key (and compare it against a reliable source - or to verify it in
person with the owner of the key).

### Risks of a lack of authentication

When we obtain an OpenPGP key from an untrusted source that claims to be
Alice's key, we cannot be sure if the key is indeed controlled by Alice
(and not by some malicious other party) - at least not without performing
additional steps for verification.

If we have not authenticated a key, there is a risk we are using a key that
is in fact controlled by a malicious third party. That party will then be
able to perform various types of attacks, including:

- send us seemingly correctly signed email (which might lead to false
confidence in the origin of a piece of email), or
- intercept the communication that we
intended to secure using encryption
(["man-in-the-middle attack"](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)).


## OpenPGP CA is useful for groups or organizations

OpenPGP CA helps organizations or groups model trust relations in OpenPGP.
It is based on the observation that they often operate as a single
trust unit.

The key assumption for OpenPGP CA to be useful is that a group of
OpenPGP users share one common trusted party who performs the role of a "CA
admin" for them.
In formal organizations that might be the existing OPSEC team. In an
informal group it might be one person who volunteers for that job and is
trusted by other team members to perform that task.

We're going to use the term "organization" in the following to refer to any
group of people who might use OpenPGP CA together - whether they are an
informal group, a commercial organization, or any other form - such as:

- Journalistic organizations
- Human rights groups
- Informal groups of activists
- ... ?!

## Lowers requirements for skills users need to learn

Deploying OpenPGP in an organization is hard.
Users need to be taught the high-level skills to 

- encrypt and sign email, as well as
- how to recognize encrypted and signed email.

Users traditionally also need help with a set of lower-level tasks, such as:

- doing key discovery,
- checking that the keys do belong to the intended party (authentication), and
- creating their own key.

OpenPGP CA simplifies or eliminates the latter tasks for users, thus
freeing up mental bandwidth to acquire the former, indispensable, high
level skills. This also reduces the risk of user errors.

## Introducing a "CA admin" role

OpenPGP CA introduces the new role of "CA admin" for OpenPGP usage in
organizations. With this role we formalize and automate a range of concerns
that OPSEC teams often try to deal with manually, or with ad-hoc in
house tooling.

The CA admin manages users' keys and their trust relations (key creation
and authentication) both within and across organizations.

This specialized role has the dual goals of 
- lowering the cognitive burden for users of OpenPGP, while at the same time
- significantly raising the bar for the security properties of OpenPGP
  usage in the organization (in particular because the CA admin
  performs authentication on user's keys).

OpenPGP CA assists the CA admin in performing these tasks (by providing
tooling that largely automates them).

## No key escrow

Centrally storing private key material of users has legitimate and at times
useful use-cases - however, it also comes with massive risks.

OpenPGP CA does not do key escrow - that is, secret key material of users
is never stored in OpenPGP CA.

## Interests of users and the OpenPGP CA admin are aligned

### Context: TLS server certificates

The concept of a certificate authority (CA) is most well known in the
context of
[TLS server certificates](https://en.wikipedia.org/wiki/Public_key_certificate#TLS/SSL_server_certificate).  

TLS certificates claim an identity (the domainname of a website). This
identity is verified and cryptographically vouched for by a CA. CAs
for TLS server certificates act as a group of globally trusted
verifiers of identity (often, but not always, for-profit).

For organizations that use TLS certificates, these CAs are external actors.

While TLS server certificates of course bring massive benefits for
secure communication on the web, there are also problems:  
The interests of CAs in the TLS space are not aligned with the interests
of their users.
For-profit CAs are driven by profit, not by the needs of users.
Law enforcement might interact with these CAs in ways that are opaque to the
users of the certificates and detrimental to their goals.  
{CA's interest: "not causing trouble for law enforcement"}

Some TLS CAs have been known to be sloppy or even malicious.
The authentication that the CAs perform is often extremely weak.

Our main observation about TLS, in this context, is that it prescribes a
centralized approach for establishing identity. To use TLS, you
are expected to trust a centrally defined set of CAs.

### In contrast: OpenPGP CA 

In contrast, OpenPGP CA facilitates a decentralized, federated approach to
trust and to establishing identities.
OpenPGP CA embraces OpenPGP's decentralized trust model, making it easy to
leverage its inherent benefits.

Compared to traditional, ad-hoc OpenPGP usage, OpenPGP CA users
delegate trust-management to the OpenPGP CA admin of their organization
(non-exclusively).

So trust management with OpenPGP CA is somewhat centralized - but only
*within* the scope of individual organizations.
Using OpenPGP CA does not require placing trust in a third party with
potentially conflicting interests, which is essential for activists,
journalists, and lawyers.

This approach acknowledges that an organization is often a reasonable unit
of trust: members of organizations usually trust their OPSEC team to make
many trust decisions anyway.

The interests of the (in-house) CA admin are strongly aligned with the
interests of the users and the organization overall.

## The most common communication partners are automatically authenticated

People often mainly communicate with others in the same
organization - and with people in one of a few affiliated organizations. 

![Image](emails.jpg "Patterns of email between users of two organizations")

When communication follows that type of pattern, users in organizations that
use OpenPGP CA can easily authenticate their most common communication
partners. This authentication is obtained with no extra effort on the part
of the user.

The consequence is that members of the organization automatically have
trusted paths to the people they communicate with most: people
within their organization, and their usual external collaborators.

{+ hint at bridging and the CA admin signing some external keys?}


## Bridges between organizations

Two affiliated organizations that use OpenPGP CA can easily set up a
"bridge" between their respective CAs.
Creating a bridge gives validated paths between all users in the two
organizations - all users in both organizations automatically see each
other's keys as authenticated.

This makes sense when the CA admins believe that the other organization's
CA admin does a good job authenticating their user's keys in OpenPGP CA.


# Advantages / disadvantages relative to the status quo

OpenPGP CA leverages existing trust structures to delegate the trust
management to a technically competent party within the organization.

{^ unpack ?}

## Benefits for users

In an OpenPGP CA-using organization, users delegate authentication to an 
in-house CA. This allows users to securely and seamlessly communicate via 
OpenPGP-encrypted email without having to manually compare fingerprints,
without having to understand OpenPGP keys or certifications, and without
having to trust an external third-party with potentially conflicting
interests.

Only users with special needs have to understand how to certify
keys. So an initial briefing for users can concentrate on understanding
higher level concepts (What does it mean when a key is authenticated? How
can I recognize if the key of my communication partner is authenticated?)
rather than lower level mechanisms (click on this menu, select that option,
etc.).


## Disadvantages

Users need to trust the CA admin - if users have no good reason to trust
the CA admin (both in terms of intention and technical know how), we're
making things worse by introducing that role.

Specifically, users need to trust the certifications introduced by the CA.
However, in many organizations users need to trust the admin/OPSEC teams
anyway (they could install malicious versions of software, etc).

The role of the CA admin centralizes a lot of tasks and responsibilities that
would otherwise be distributed between all users. The CA admin key centralizes
certain types of risk.

## Benefits for Admins

OpenPGP CA vastly improves the capabilities of the administrator by
giving them tooling to model *existing* trust relationships in their
organization.

Traditionally, tooling in the OpenPGP ecosystem was mainly aimed
at users. Dedicated administrators of OpenPGP setups have built ad-hoc
tools for tasks they perform, but these were point solutions, and often
incomplete.

OpenPGP CA is a general-purpose tool for both small and large organizations.
We propose a systematic framework for working with keys and
certifications and support putting this approach in practice.

The benefits of OpenPGP CA are - at least in theory - not particular to
OpenPGP CA: a dedicated administrator could perform all of the relevant tasks
manually.
However, in practice, these tasks are so hard for administrators to
perform correctly with existing tooling that no one uses this type of
setup.

While OpenPGP CA prescribes some aspects of how OpenPGP keys and
certifications should be handled, our approach offers [some degrees of
freedom](ch3.md), so that security specialists in organizations can tailor
usage to their specific needs.
That said, our framework/paradigm makes OpenPGP key management less ad-hoc and
more systematic.


## Doesn't require a radical departure from existing OpenPGP practices

Because OpenPGP CA works within the existing OpenPGP framework {< clarify
/simplify!},
users do not need any new software to take advantage of OpenPGP CA's
benefits. They can continue to use existing email clients and encryption
plugins. Further, OpenPGP CA can co-exist with other authentication
approaches, like traditional key certification workflows.

OpenPGP CA can be rolled out gradually within an organization.

# Is OpenPGP CA suitable for my use case?

- OpenPGP CA can be useful for organizations or informal groups (individual
  OpenPGP users are probably not going to benefit from using OpenPGP CA)
- There needs to be a shared trusted party in the organization who can perform
  the OpenPGP CA admin role.  
  The CA admin needs to have the relevant knowledge as well as skillset,
  and users must trust them to do authentication on their behalf.
- A significant share of encrypted communication happens between users within
  the organization, or with affiliated persons or organizations that are
  integrated into the OpenPGP CA ecosystem of their organization.  
  (Either the CA admin authenticates individual external keys,
  or a bridge is set up with an affiliated organization)
- When these conditions are met, OpenPGP CA gives users the advantage of
  automatically authenticated keys for their main communication
  partners, while reducing the work of managing keys and offering a
  framework for all OpenPGP related activities. 
