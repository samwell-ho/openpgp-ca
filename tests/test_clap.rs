#[macro_use]
extern crate clap;

use clap::App;


#[test]
fn load_config() {
    // try to load the clap yaml config file
    // (will panic if config is broken)
    let yaml = load_yaml!("../src/cli.yml");
    let app = App::from_yaml(yaml);

    // check if App is happy
    let name: &str = app.get_name();
    assert_eq!(name, "openpgp-ca");
}