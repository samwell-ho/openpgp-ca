# SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

# Stage 0: build OpenPGP CA binaries
FROM rust:buster as builder

# Sequoia dependencies
# https://gitlab.com/sequoia-pgp/sequoia#debian
RUN DEBIAN_FRONTEND=noninteractive apt-get -q update && \
    apt-get -q -y --no-install-recommends install \
    git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev

# Build OpenPGP CA
ADD ./ /opt/openpgp-ca/
RUN cd /opt/openpgp-ca/ && cargo build --release


# Stage 1: build base Docker image
FROM debian:buster-slim as base

# Sequoia dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get -q update && \
    apt-get -q -y --no-install-recommends install \
    nettle-dev libssl-dev capnproto libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*

# OpenPGP CA database file
ENV OPENPGP_CA_DB=/var/run/openpgp-ca/openpgp-ca.sqlite

VOLUME ["/var/run/openpgp-ca/"]


# Stage 2: build "openpgp-ca-restd" Docker image
FROM base as openpgp-ca-restd

COPY --from=builder /opt/openpgp-ca/target/release/openpgp-ca-restd /usr/local/bin/openpgp-ca-restd

ENV ROCKET_ADDRESS=0.0.0.0

ENTRYPOINT ["/usr/local/bin/openpgp-ca-restd"]
CMD ["run"]


# Stage 3: build "openpgp-ca" Docker image
#
# NOTE: the last target is default for -t,
# putting this stage last makes openpgp-ca the "default image"
FROM base as openpgp-ca

COPY --from=builder /opt/openpgp-ca/target/release/oca /usr/local/bin/oca

ENTRYPOINT ["/usr/local/bin/oca"]
CMD ["--help"]