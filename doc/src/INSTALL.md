# Installation

OpenPGP CA requires:

- Rust and Cargo, see https://www.rust-lang.org/tools/install

- the C-dependencies of Sequoia PGP, see "Building Sequoia" at https://gitlab.com/sequoia-pgp/sequoia

Then run `cargo build --release` - the resulting binary is at `target/release/openpgp-ca`  

It's possible to run OpenPGP CA in Docker, [see below](#running-in-docker).
