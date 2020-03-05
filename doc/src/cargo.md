# Examples for running openpgp-ca from cargo:

When working on the rust source code of OpenPGP CA, it is convenient to run
the commandline utility directly from cargo (without building and using
the `openpgp-ca` binary that is usually run):

```
cargo run ca init example.org
cargo run -- -d /tmp/ca.sqlite ca init example.org

cargo run user add --email alice@example.org --email a@example.org --name "Alice Adams"
```
