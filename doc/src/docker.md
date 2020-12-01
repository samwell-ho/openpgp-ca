<!--
SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: GPL-3.0-or-later
-->

## Running in Docker

You can also use `openpgp-ca` in [Docker](https://www.docker.com/).

The OpenPGP CA repository contains a dockerfile at `/Dockerfile` that
helps you build and use the `openpgp-ca` tool.

Building is done by running:

```
$ docker build --tag openpgp-ca ./
```

This will build the image and tag it as `openpgp-ca`. Once built, you can run it as:

```
$ docker run openpgp-ca
```

You should see the help output. Running any `openpgp-ca` command is easy, just add it at the end, like so:

```
$ docker run openpgp-ca ca init example.org
```

However, since it's running in Docker, the database does not persist. The database is kept in `/var/run/openpgp-ca/` inside the container. Therefore, you might want to do a volume-mount:

```
$ docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca ca init example.org
```

An example centralized workflow of creating a CA and a user would thus be:

```
$ docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca ca init example.org
$ docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user add --email alice@example.org --email a@example.org --name Alicia
$ docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user add --email bob@example.org
$ docker run -v "/some/host/directory/:/var/run/openpgp-ca/" openpgp-ca user list
```

Obviously for regular use you might use more automated tools like
[`docker-compose`](https://docs.docker.com/compose/).

## Container Registry

You can find our pre-built
[container images on gitlab](https://gitlab.com/openpgp-ca/openpgp-ca/container_registry/).

The "latest" tag can be used from
[registry.gitlab.com/openpgp-ca/openpgp-ca:latest](registry.gitlab.com/openpgp-ca/openpgp-ca:latest)

## Example usage

First, let's create a volume to store the OpenPGP CA database (which
contains all of the state of this OpenPGP CA instance)

```
$ docker volume create example_ca
```

Then we can run a temporary container that uses this
volume and the latest OpenPGP CA build from our GitLab CI (of course you
can always build your own image, if you prefer):

```
$ docker container run --rm \
   -v example_ca:/var/run/openpgp-ca/ \
   registry.gitlab.com/openpgp-ca/openpgp-ca:latest
```

To initialize an OpenPGP CA instance for the domain `example.org`, we run

```
$ docker container run --rm \
   -v example_ca:/var/run/openpgp-ca/ \
   registry.gitlab.com/openpgp-ca/openpgp-ca:latest \
   ca init example.org
```

We create a new user:

```
$ docker container run --rm \
   -v example_ca:/var/run/openpgp-ca/ \
   registry.gitlab.com/openpgp-ca/openpgp-ca:latest \
   user add --email alice@example.org --name "Alice Adams"
```

... and then inspect the user database:

```
$ docker container run --rm \
   -v example_ca:/var/run/openpgp-ca/ \
   registry.gitlab.com/openpgp-ca/openpgp-ca:latest \
   user list

OpenPGP key for 'Alice Adams'
 fingerprint 4D3B3C810C5A1383967C48E74825DDCB02A64CCB
 user cert (or subkey) signed by CA: true
 user cert has tsigned CA: true
 - email alice@example.org
 no expiration date is set for this user key
 1 revocation certificate(s) available
```
