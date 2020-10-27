# SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

FROM rust:buster

# Sequoia dependencies
# https://gitlab.com/sequoia-pgp/sequoia#debian
RUN DEBIAN_FRONTEND=noninteractive apt-get -q update && \
    apt-get -q -y --no-install-recommends install \
    git rustc cargo clang make pkg-config nettle-dev libssl-dev capnproto libsqlite3-dev

# OpenPGP CA database file
ENV OPENPGP_CA_DB=/var/run/openpgp-ca/openpgp-ca.sqlite

# OpenPGP CA
ADD ./ /opt/openpgp-ca/
RUN cd /opt/openpgp-ca/ && cargo build --release
RUN cp /opt/openpgp-ca/target/release/openpgp-ca /usr/local/bin/
RUN cp /opt/openpgp-ca/target/release/openpgp-ca-restd /usr/local/bin/

VOLUME ["/var/run/openpgp-ca/"]
ENTRYPOINT ["/usr/local/bin/openpgp-ca"]
CMD ["--help"]
