use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use failure::Fail;
use tempfile;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[macro_export]
macro_rules! make_context {
    () => {{
        let ctx = match Context::ephemeral() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is GnuPG installed?", e);
                return;
            },
        };
        match ctx.start("gpg-agent") {
            Ok(_) => (),
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is the GnuPG agent installed?", e);
                return;
            },
        }
        ctx
    }};
}

/// A GnuPG context.
#[derive(Debug)]
pub struct Context {
    homedir: Option<PathBuf>,
    components: BTreeMap<String, PathBuf>,
    directories: BTreeMap<String, PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    #[allow(dead_code)] // We keep it around for the cleanup.
    ephemeral: Option<tempfile::TempDir>,
}

impl Context {
    /// Creates a new context for the default GnuPG home directory.
    pub fn new() -> Result<Self> {
        Self::make(None, None)
    }

    /// get the homedir Path
    pub fn get_homedir(&self) -> &Path {
//        String::from(self.homedir.as_ref().unwrap().to_str().unwrap())
        self.homedir.as_ref().unwrap().as_path()
    }

    /// Creates a new context for the given GnuPG home directory.
    pub fn with_homedir<P>(homedir: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Self::make(Some(homedir.as_ref()), None)
    }

    /// Creates a new ephemeral context.
    ///
    /// The created home directory will be deleted once this object is
    /// dropped.
    pub fn ephemeral() -> Result<Self> {
        Self::make(None, Some(tempfile::tempdir()?))
    }

    fn make(homedir: Option<&Path>, ephemeral: Option<tempfile::TempDir>)
            -> Result<Self> {
        let mut components: BTreeMap<String, PathBuf> = Default::default();
        let mut directories: BTreeMap<String, PathBuf> = Default::default();
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let homedir: Option<PathBuf> =
            ephemeral.as_ref().map(|tmp| tmp.path()).or(homedir)
                .map(|p| p.into());

        for fields in Self::gpgconf(
            &homedir, &["--list-components"], 3)?.into_iter()
            {
                components.insert(String::from_utf8(fields[0].clone())?,
                                  String::from_utf8(fields[2].clone())?.into());
            }

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)?.into_iter()
            {
                let (mut key, value) = (fields[0].clone(), fields[1].clone());
                if key.ends_with(b"-socket") {
                    let l = key.len();
                    key.truncate(l - b"-socket".len());
                    sockets.insert(String::from_utf8(key)?,
                                   String::from_utf8(value)?.into());
                } else {
                    directories.insert(String::from_utf8(key)?,
                                       String::from_utf8(value)?.into());
                }
            }

        Ok(Context {
            homedir,
            components,
            directories,
            sockets,
            ephemeral,
        })
    }

    fn gpgconf(homedir: &Option<PathBuf>, arguments: &[&str], nfields: usize)
               -> Result<Vec<Vec<Vec<u8>>>> {
        let nl = |&c: &u8| c as char == '\n';
        let colon = |&c: &u8| c as char == ':';

        let mut gpgconf = Command::new("gpgconf");
        if let Some(homedir) = homedir {
            gpgconf.arg("--homedir").arg(homedir);

            // https://dev.gnupg.org/T4496
            gpgconf.env("GNUPGHOME", homedir);
        }

        for argument in arguments {
            gpgconf.arg(argument);
        }
        let output = gpgconf.output().map_err(|e| -> failure::Error {
            Error::GPGConf(e.to_string()).into()
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for line in output.stdout.split(nl) {
                if line.len() == 0 {
                    // EOF.
                    break;
                }

                let fields =
                    line.splitn(nfields, colon).map(|f| f.to_vec())
                        .collect::<Vec<_>>();

                if fields.len() != nfields {
                    return Err(Error::GPGConf(
                        format!("Malformed response, expected {} fields, \
                                 on line: {:?}", nfields, line)).into());
                }

                result.push(fields);
            }
            Ok(result)
        } else {
            Err(Error::GPGConf(String::from_utf8_lossy(
                &output.stderr).into_owned()).into())
        }
    }

    /// Returns the path to a GnuPG component.
    pub fn component<C>(&self, component: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.components.get(component.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                Error::GPGConf(format!("No such component {:?}",
                                       component.as_ref())).into()
            })
    }

    /// Returns the path to a GnuPG directory.
    pub fn directory<C>(&self, directory: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.directories.get(directory.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                Error::GPGConf(format!("No such directory {:?}",
                                       directory.as_ref())).into()
            })
    }

    /// Returns the path to a GnuPG socket.
    pub fn socket<C>(&self, socket: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.sockets.get(socket.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                Error::GPGConf(format!("No such socket {:?}",
                                       socket.as_ref())).into()
            })
    }

    /// Creates directories for RPC communication.
    pub fn create_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--create-socketdir"], 1)?;
        Ok(())
    }

    /// Removes directories for RPC communication.
    ///
    /// Note: This will stop all servers once they note that their
    /// socket is gone.
    pub fn remove_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--remove-socketdir"], 1)?;
        Ok(())
    }

    /// Starts a GnuPG component.
    pub fn start(&self, component: &str) -> Result<()> {
        self.create_socket_dir()?;
        Self::gpgconf(&self.homedir, &["--launch", component], 1)?;
        Ok(())
    }

    /// Stops a GnuPG component.
    pub fn stop(&self, component: &str) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--kill", component], 1)?;
        Ok(())
    }

    /// Stops all GnuPG components.
    pub fn stop_all(&self) -> Result<()> {
        self.stop("all")
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
    }
}

#[derive(Fail, Debug)]
/// Errors used in this module.
pub enum Error {
    /// Errors related to `gpgconf`.
    #[fail(display = "gpgconf: {}", _0)]
    GPGConf(String),
    /// The remote operation failed.
    #[fail(display = "Operation failed: {}", _0)]
    OperationFailed(String),
    /// The remote party violated the protocol.
    #[fail(display = "Protocol violation: {}", _0)]
    ProtocolError(String),

}

pub fn gpg_import(ctx: &Context, what: &[u8]) {
    use std::process::Stdio;

    println!("homedir {:?}", ctx.directory("homedir").unwrap());

    let mut gpg = Command::new("gpg")
        .stdin(Stdio::piped())
        .arg("--homedir").arg(ctx.directory("homedir").unwrap())
        .arg("--import")
        .spawn()
        .expect("failed to start gpg");
    gpg.stdin.as_mut().unwrap().write_all(what).unwrap();
    let status = gpg.wait().unwrap();
    assert!(status.success());
}
