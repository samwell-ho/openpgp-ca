# Calibrating OpenPGP CA security/usability tradeoffs 

OpenPGP CA prescribes some aspects of how to use OpenPGP within an organization. However, there are also some degrees of freedom in how to deploy OpenPGP CA. Organizations need to make some decisions before rolling out OpenPGP CA.


## Does my organization need an offline OpenPGP CA, or is an online instance okay?

The OpenPGP CA database currently contains the private key of the CA.
This key can create certifications that all users in the organization trust
implicitly. If an attacker can get control of the CA key, they can
certify keys to perform man-in-the-middle attacks on users.

If this scenario is an unacceptable risk, OpenPGP CA can be
run on an airgapped ("offline") system.

The OpenPGP CA database itself is not encrypted or otherwise protected, and
the CA key is not currently password protected. This means that the
database file needs to be protected appropriately (e.g. stored on
removable encrypted storage).


## Should my organization use the centralized or decentralized workflows?
  
Centralized key creation is a convenient workflow, but it means that
the CA admin has access to the users' private keys during key creation.

This means that if the CA admin machine is compromised, an attacker may get
access to new users' private key material.

This workflow also opens the possibility that law enforcement (or other
actors) could coerce the CA admin to disclose private key material. 

If a third party has access to the private key material of a user, they can
read messages that are encrypted to the user, as well as forge
signatures and certifications. 

The decentralized workflow avoids these pitfalls, but makes adding new users
more cumbersome: not only the key, but also the certifications and the
revocation certificates need to be created on the user's system, and sent
to the OpenPGP CA admin.  The main focus of the next version of OpenPGP CA
is simplifing this workflow by adding support to GPG Sync to do the initial setup.


## Should keys be public?

Some individuals shouldn't be readily associated with an organization.  For
instance, a journalist may work for some organization, but that association should
not be published.  In these cases, it is best to not only not give such users
an email address, but the user's key should not be publicly certified.
Such keys could be added to a private GPG Sync-style keylist.  But, even this should
be done with care.
