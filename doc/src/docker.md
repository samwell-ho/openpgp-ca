## Running in Docker

You can also use `openpgp-ca` in [Docker](https://www.docker.com/). Building boils down to:

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

Obviously for regular use you might use more automated tools like [`docker-compose`](https://docs.docker.com/compose/).
