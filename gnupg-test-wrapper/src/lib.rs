// Copyright 2019-2021 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::collections::HashMap;

use std::fmt;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use csv::StringRecord;
use rexpect::session::spawn_command;

/// A simple wrapper for GnuPG, for use in OpenPGP CA integration tests.
///
/// NOTE: This wrapper is not defensively written.
/// It is absolutely not intended for production PGP usage!
///
/// NOTE: gpg.wait() may deadlock if the child process stdout pipe is full.
/// This doesn't seem to be a problem for the current set of tests, but is a
/// limitation of this wrapper.

pub fn make_context() -> Result<Ctx> {
    let ctx = Ctx::ephemeral().context(
        "SKIP: Failed to create GnuPG context. Is GnuPG installed?",
    )?;

    ctx.start("gpg-agent").context(
        "SKIP: Failed to to start gpg-agent. Is the GnuPG agent installed?",
    )?;

    Ok(ctx)
}

/// A GnuPG context.
#[derive(Debug)]
pub struct Ctx {
    homedir: Option<PathBuf>,
    components: BTreeMap<String, PathBuf>,
    directories: BTreeMap<String, PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    #[allow(dead_code)] // We keep it around for the cleanup.
    ephemeral: Option<tempfile::TempDir>,
}

impl Ctx {
    /// Creates a new context for the default GnuPG home directory.
    pub fn new() -> Result<Self> {
        Self::make(None, None)
    }

    /// get the homedir Path
    pub fn get_homedir(&self) -> &Path {
        self.homedir.as_ref().unwrap().as_path()
    }

    /// Creates a new context for the given GnuPG home directory.
    pub fn with_homedir<P>(homedir: P) -> Result<Self>
    where
        P: AsRef<Path>,
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

    /// don't delete home directory.
    /// this is intended for manually debugging data that was created in a
    /// test-run.
    pub fn leak_tempdir(&mut self) -> Option<PathBuf> {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
        self.ephemeral.take().map(tempfile::TempDir::into_path)
    }

    fn make(
        homedir: Option<&Path>,
        ephemeral: Option<tempfile::TempDir>,
    ) -> Result<Self> {
        let mut components: BTreeMap<String, PathBuf> = Default::default();
        let mut directories: BTreeMap<String, PathBuf> = Default::default();
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let homedir: Option<PathBuf> = ephemeral
            .as_ref()
            .map(|tmp| tmp.path())
            .or(homedir)
            .map(|p| p.into());

        for fields in
            Self::gpgconf(&homedir, &["--list-components"], 3)?.into_iter()
        {
            components.insert(
                String::from_utf8(fields[0].clone())?,
                String::from_utf8(fields[2].clone())?.into(),
            );
        }

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)?.into_iter()
        {
            let (mut key, value) = (fields[0].clone(), fields[1].clone());
            if key.ends_with(b"-socket") {
                let l = key.len();
                key.truncate(l - b"-socket".len());
                sockets.insert(
                    String::from_utf8(key)?,
                    String::from_utf8(value)?.into(),
                );
            } else {
                directories.insert(
                    String::from_utf8(key)?,
                    String::from_utf8(value)?.into(),
                );
            }
        }

        Ok(Ctx {
            homedir,
            components,
            directories,
            sockets,
            ephemeral,
        })
    }

    fn gpgconf(
        homedir: &Option<PathBuf>,
        arguments: &[&str],
        nfields: usize,
    ) -> Result<Vec<Vec<Vec<u8>>>> {
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
        let output = gpgconf.output().map_err(|e| -> anyhow::Error {
            GnupgError::GgpConf(e.to_string()).into()
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for line in output.stdout.split(nl) {
                if line.is_empty() {
                    // EOF.
                    break;
                }

                let fields = line
                    .splitn(nfields, colon)
                    .map(|f| f.to_vec())
                    .collect::<Vec<_>>();

                if fields.len() != nfields {
                    return Err(GnupgError::GgpConf(format!(
                        "Malformed response, expected {} fields, \
                         on line: {:?}",
                        nfields, line
                    ))
                    .into());
                }

                result.push(fields);
            }
            Ok(result)
        } else {
            Err(GnupgError::GgpConf(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
            .into())
        }
    }

    /// Returns the path to a GnuPG component.
    pub fn component<C>(&self, component: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.components
            .get(component.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GgpConf(format!(
                    "No such component {:?}",
                    component.as_ref()
                ))
                .into()
            })
    }

    /// Returns the path to a GnuPG directory.
    pub fn directory<C>(&self, directory: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.directories
            .get(directory.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GgpConf(format!(
                    "No such directory {:?}",
                    directory.as_ref()
                ))
                .into()
            })
    }

    /// Returns the path to a GnuPG socket.
    pub fn socket<C>(&self, socket: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.sockets
            .get(socket.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GgpConf(format!(
                    "No such socket {:?}",
                    socket.as_ref()
                ))
                .into()
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

    pub fn import(&self, what: &[u8]) {
        let mut gpg = self
            .build_gpg_command(&["--import"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to start gpg");

        gpg.stdin.as_mut().unwrap().write_all(what).unwrap();
        let status = gpg.wait().unwrap();
        assert!(status.success());
    }

    pub fn export(&self, search: &str) -> String {
        let mut gpg = self
            .build_gpg_command(&["--armor", "--export", search])
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to start gpg");

        let status = gpg.wait().unwrap();
        assert!(status.success());

        let mut out = String::new();
        gpg.stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();

        out
    }

    pub fn export_secret(&self, search: &str) -> String {
        let mut gpg = self
            .build_gpg_command(&["--armor", "--export-secret-keys", search])
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to start gpg");

        let status = gpg.wait().unwrap();
        assert!(status.success());

        let mut out = String::new();
        gpg.stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();

        out
    }

    pub fn list_keys(&self) -> Result<HashMap<String, String>> {
        let res = self.list_keys_raw();

        // filter: keep only the "uid" lines
        let uids = res
            .iter()
            .filter(|&line| line.get(0) == Some("uid"))
            .cloned()
            .collect::<Vec<_>>();

        // map: uid -> trust
        Ok(uids
            .iter()
            .map(|u| {
                (u.get(9).unwrap().to_owned(), u.get(1).unwrap().to_owned())
            })
            .collect())
    }

    fn list_keys_raw(&self) -> Vec<StringRecord> {
        let gpg = self
            .build_gpg_command(&["--list-keys", "--with-colons"])
            .output()
            .expect("failed to start gpg");

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(b':')
            .flexible(true)
            .from_reader(gpg.stdout.as_slice());

        let status = gpg.status;
        assert!(status.success());

        rdr.records().map(|rec| rec.unwrap()).collect()
    }

    pub fn edit_trust(&self, user_id: &str, trust: u8) -> Result<()> {
        let gpg = self.build_gpg_command(&["--edit-key", user_id]);

        let mut p = spawn_command(gpg, Some(10_000)).unwrap();

        p.exp_string("gpg>").unwrap();
        p.send_line("trust").unwrap();
        p.exp_string("Your decision?").unwrap();
        p.send_line(&format!("{}", trust)).unwrap();
        p.exp_string(
            "Do you really want to set this key to ultimate trust? (y/N)",
        )
        .unwrap();
        p.send_line("y").unwrap();
        p.exp_string("gpg>").unwrap();
        p.send_line("quit").unwrap();
        p.exp_eof().unwrap();

        Ok(())
    }

    pub fn make_revocation(
        &self,
        user_id: &str,
        filename: &str,
        reason: u8,
    ) -> Result<()> {
        let gpg = self.build_gpg_command(&[
            "--output",
            filename,
            "--gen-revoke",
            user_id,
        ]);

        let mut p = spawn_command(gpg, Some(10_000)).unwrap();

        p.exp_string("Create a revocation certificate for this key? (y/N)")
            .unwrap();
        p.send_line("y").unwrap();
        p.exp_string("Your decision?").unwrap();
        p.send_line(&format!("{}", reason)).unwrap();
        p.exp_string(">").unwrap();
        p.send_line("").unwrap();
        p.exp_string("Is this okay? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_eof().unwrap();

        Ok(())
    }

    pub fn edit_expire(&self, user_id: &str, expires: &str) -> Result<()> {
        let gpg = self.build_gpg_command(&["--edit-key", user_id]);

        let mut p = spawn_command(gpg, Some(10_000)).unwrap();

        p.exp_string("gpg>").unwrap();
        p.send_line("expire").unwrap();
        p.exp_string("Key is valid for? (0)").unwrap();
        p.send_line(expires).unwrap();
        p.exp_string("Is this correct? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_string("gpg>").unwrap();
        p.send_line("quit").unwrap();
        p.exp_string("Save changes? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_eof().unwrap();

        Ok(())
    }

    pub fn create_user(&self, user_id: &str) {
        let mut gpg = self
            .build_gpg_command(&[
                "--quick-generate-key",
                "--batch",
                "--passphrase",
                "",
                user_id,
            ])
            .spawn()
            .expect("failed to start gpg");

        let status = gpg.wait().unwrap();
        assert!(status.success());
    }

    pub fn sign(&self, user_id: &str) -> Result<()> {
        let gpg = self.build_gpg_command(&["--edit-key", user_id]);

        let mut p = spawn_command(gpg, Some(10_000)).unwrap();

        p.exp_string("gpg>").unwrap();
        p.send_line("sign").unwrap();
        p.exp_string("Really sign? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_string("gpg>").unwrap();
        p.send_line("save").unwrap();
        p.exp_eof().unwrap();

        Ok(())
    }

    pub fn tsign(&self, user_id: &str, level: u8, trust: u8) -> Result<()> {
        let gpg = self.build_gpg_command(&["--edit-key", user_id]);

        let mut p = spawn_command(gpg, Some(10_000)).unwrap();

        p.exp_string("gpg>").unwrap();
        p.send_line("tsign").unwrap();
        p.exp_string("Your selection?").unwrap();
        p.send_line(&format!("{}", trust)).unwrap();
        p.exp_string("Your selection?").unwrap();
        p.send_line(&format!("{}", level)).unwrap();
        p.exp_string("Your selection?").unwrap();
        p.send_line("").unwrap(); // domain
        p.exp_string("Really sign? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_string("gpg>").unwrap();
        p.send_line("quit").unwrap();
        p.exp_string("Save changes? (y/N)").unwrap();
        p.send_line("y").unwrap();
        p.exp_eof().unwrap();

        Ok(())
    }

    /// Build a 'Command' for running gpg with homedir set according to
    /// this Ctx, "LC_ALL=C", and a list of additional args.
    fn build_gpg_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.env("LC_ALL", "C")
            .arg("--homedir")
            .arg(self.directory("homedir").unwrap());

        args.iter().for_each(|&arg| {
            cmd.arg(arg);
        });

        cmd
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
    }
}

impl std::error::Error for GnupgError {}

impl fmt::Display for GnupgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GnupgError::GgpConf(s) => write!(f, "gpgconf: {}", s),
            GnupgError::OperationFailed(s) => {
                write!(f, "Operation failed: {}", s)
            }
            GnupgError::ProtocolError(s) => {
                write!(f, "Protocol violation: {}", s)
            }
        }
    }
}

#[derive(Debug)]
/// Errors used in this module.
pub enum GnupgError {
    /// Errors related to `gpgconf`.
    GgpConf(String),

    /// The remote operation failed.
    OperationFailed(String),

    /// The remote party violated the protocol.
    ProtocolError(String),
}
