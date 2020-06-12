# Installation

OpenPGP CA requires:

- Rust and Cargo, see https://www.rust-lang.org/tools/install

- the C-dependencies of Sequoia PGP, see "Building Sequoia" at https://gitlab.com/sequoia-pgp/sequoia

Get the OpenPGP-CA source-code from https://gitlab.com/openpgp-ca/openpgp-ca,
then run
 
`$ cargo build --release`
 
The resulting binary is generated at `target/release/openpgp-ca`  

It's possible to run OpenPGP CA in Docker, [see here](docker.md).
