This example shows how to set up a "bridge" between two OpenPGP CA using
organizations. The purpose of bridging is that users between organizations
automatically are mutually authenticated.
Any user at one organization sees the OpenPGP keys of users at the other
organization as verified - the authentication that is done by the OpenPGP
CA admin at each organization is shared between both organizations.

Such a bridge is configured when the CA Admins at both organizations are
satisfied that the CA Admin of the other organization is following good
procedures in signing keys of users within their organization.

The end result is that users can seamlessly authenticate users in the
other organization, and vice versa.

In this example we set up users as shown in the "centralized key creation"
workflow, above.  
Two independent instances of OpenPGP CA are set up, users are created in each
instance. Then a "bridge" is configured between both OpenPGP CA instances.

## Part 1: Set up OpenPGP CA instance 1
 
Set up an OpenPGP CA instance for our first organization, `some.org` and
create a new user:

`$ openpgp-ca -d some.oca ca init some.org`

`$ openpgp-ca -d some.oca user add --email alice@some.org --name "Alice Adams"`

We will need the public key of the OpenPGP CA admin to set up the bridge
from the second organization, so we export it:

`$ openpgp-ca -d some.oca ca export > some.pub`

## Part 2: Set up OpenPGP CA instance 2

Set up an OpenPGP CA instance for our second organization, `other.org` and
create a new user:

`$ openpgp-ca -d other.oca ca init other.org`

`$ openpgp-ca -d other.oca user add --email bob@other.org --name "Bob Baker"`

We will need the public key of the OpenPGP CA admin to set up the bridge
from the first organization, so we export it:

`$ openpgp-ca -d other.oca ca export > other.pub`

## Part 3: OpenPGP CA instance 1 configures bridge
 
Now we are going to set up the bridge from the side of the first organization
 `some.org`.
Taking this step means that the OpenPGP CA admin at `some.org` trusts the
OpenPGP CA admin at the second organization, `other.org`, to correctly
authenticate users within their organization.

### Configure bridge to instance 2

Setting up this bridge means that CA 1 creates a trust signature for the
public key of the remote organization (in this case, `other.org`).
This trust signature is implicitly scoped to the domainname `other.org` by
OpenPGP CA.

`$ openpgp-ca -d some.oca bridge new --remote-key-file other.pub`

OpenPGP CA prints a message showing the fingerprint of the remote key
that you just configured a bridge to. Please double-check that this
fingerprint really belongs to the intended remote CA admin before
disseminating the newly trust-signed public key!

### Export keys

For the bridge to take effect, the certification we just generated needs to
be published. To this end, we export our newly signed version of the public
key of CA 2 (other.org):

`$ openpgp-ca -d some.oca bridge list > other.signed`

Independently, we export the user keys at `some.org`, for testing, below.

`$ openpgp-ca -d some.oca user export > some.users`

## Part 4: OpenPGP CA instance 2 configures bridge

Analogous to the previous step, we now set up the bridge in the other
direction. The OpenPGP CA admin at `other.org` creates a certification for
the OpenPGP CA admin key of `some.org`.

CA 2 creates a trust signature for the public key of CA 1 (implicitly
scoped to the domainname "some.org") of the remote organization (again,
please make sure that the fingerprint belongs to the intended remote CA!)

`$ openpgp-ca -d other.oca bridge new --remote-key-file some.pub`

### Export keys

As above, we export the public key of CA 1 (some.org) that now includes
the certification we just created:

`$ openpgp-ca -d other.oca bridge list > some.signed`

We also export the user keys at `other.org`, for testing in the next step.

`$ openpgp-ca -d other.oca user export > other.users`

## Part 5: Import all keys into "Alice"s GnuPG environment, confirm authentication

Now we import all of the keys we exported above to see how the bridge will
look from a user's point of view. We're going to do this as `alice@some.org`.

### Setting up a GnuPG test environment 

For testing purposes, you'll want to create a separate test environment.
Using GnuPG, this can be done as follows:

`$ mkdir /tmp/test/ && chmod 0700 /tmp/test`
`$ export GNUPGHOME=/tmp/test/`

### Import user keys and CA admin keys of both organizations

`$ gpg --import some.signed other.signed some.users other.users`

### Set ownertrust for Alice

Alice now marks her own key as "trusted", signifying that Alice considers
this key as her own:

`$ gpg --edit-key alice@some.org`

Then `trust`, `5`, `quit`.

### Inspect authentication in Alice's GnuPG instance 

Now we can check what Alice (who works at `some.org`) sees in
her OpenPGP instance:

`$ gpg --list-keys`

GnuPG shows "ultimate" trust for Alice's own key (we configured that in the
previous step), and "full" trust for both OpenPGP CA admin keys, as well as
for Bob (who works at `other.org`):

So Alice now has an authenticated path to Bob in the web of trust. Alice
will also automatically have authenticated paths to any other users that
will be set up at `other.org`.

# Variation on the bridging Workflow example:

In "Part 2", CA 2 creates an additional user outside of the domain `other.org`:

`$ openpgp-ca user add --email carol@third.org --name "Carol Cruz"`

The rest of the workflow is performed exactly as above.

Alice can still authenticate both OpenPGP CA admin keys, as well as
Bob. Carol however is (correctly) shown as not authenticated.

{add more context/explanation}
