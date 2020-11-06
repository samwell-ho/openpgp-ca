This document aims to enumerate and clarify alternative terms that have been
used for the same concept in the OpenPGP space, as well as to document
terminology specific to OpenPGP CA.

- Authentication
- Bridge: Two instances of OpenPGP CA mark each other as (scoped) trusted
  introducers, which means that users in both organizations see each other
  as authenticated
- Certification ("Signature" on a certificate)
- Key / OpenPGP Key (Certificate)
- Key creation workflow: centralized/decentralized
- OpenPGP
- Revocation certificate
- Trust signature ("tsig"), a speficic type of certification for a
 certificate, which marks that key as a "trusted introducer" (i.e. the
  party that creates the trust signature signals that they will trust
  certifications that the "trusted introducer" makes on certificates)
