// Copyright 2019-2020 Heiko Schaefer heiko@schaefer.name
//
// This file is part of OpenPGP CA.
//
// OpenPGP CA is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPGP CA is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPGP CA.  If not, see <https://www.gnu.org/licenses/>.

use sequoia_openpgp as openpgp;

use openpgp::armor;
use openpgp::cert;
use openpgp::cert::components::Amalgamation;
use openpgp::crypto::KeyPair;
use openpgp::packet::signature;
use openpgp::packet::{Signature, UserID};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::types::KeyFlags;
use openpgp::types::{ReasonForRevocation, SignatureType};
use openpgp::{Cert, Fingerprint, KeyHandle, Packet};

use std::time::SystemTime;

use failure::{self, Fallible, ResultExt};
use sequoia_openpgp::RevocationStatus;
use std::path::PathBuf;

pub struct Pgp {}

impl Pgp {
    fn diceware() -> String {
        // FIXME: configurable dictionaries, ... ?
        use chbs::passphrase;
        passphrase()
    }

    fn user_id(email: &str, name: Option<&str>) -> UserID {
        match name {
            Some(name) => UserID::from(format!("{} <{}>", name, email)),
            None => UserID::from(format!("<{}>", email)),
        }
    }

    /// make a private CA key
    pub fn make_ca_cert(
        domainname: &str,
        name: Option<&str>,
    ) -> Fallible<(Cert, Signature)> {
        // FIXME: should not be encryption capable (?)
        // FIXME: should not have subkeys

        // Generate a Cert, and create a keypair from the primary key.
        let (cert, sig) = cert::CertBuilder::new()
            .add_signing_subkey()
            // FIXME: set expiration from CLI
            // std::time::Duration::new(123456, 0)
            .set_expiration_time(None)
            .generate()?;

        let mut keypair = cert
            .primary_key()
            .key()
            .clone()
            .mark_parts_secret()?
            .into_keypair()?;

        // Generate a userid and a binding signature.
        let email = format!("openpgp-ca@{}", domainname);
        let userid = Self::user_id(&email, name);

        let policy = StandardPolicy::new();

        let direct_key_sig = cert
            .primary_key()
            .with_policy(&policy, None)?
            .binding_signature();
        let builder = signature::Builder::from(direct_key_sig.clone())
            .set_type(SignatureType::PositiveCertification)
            .set_key_flags(&KeyFlags::empty().set_certification(true))?
            // notation: "openpgp-ca:domain=domain1;domain2"
            .add_notation(
                "openpgp-ca",
                (format!("domain={}", domainname)).as_bytes(),
                signature::subpacket::NotationDataFlags::default()
                    .set_human_readable(true),
                false,
            )?;
        let binding = userid.bind(&mut keypair, &cert, builder)?;

        // Now merge the userid and binding signature into the Cert.
        let cert = cert.merge_packets(vec![userid.into(), binding.into()])?;

        Ok((cert, sig))
    }

    /// Makes a user Cert with "emails" as UIDs.
    pub fn make_user_cert(
        emails: &[&str],
        name: Option<&str>,
        password: bool,
    ) -> Fallible<(Cert, Signature, Option<String>)> {
        // FIXME: use passphrase

        let pass = if password {
            Some(Self::diceware())
        } else {
            None
        };

        let mut builder = cert::CertBuilder::new()
            .add_subkey(
                KeyFlags::default()
                    .set_transport_encryption(true)
                    .set_storage_encryption(true),
                None,
            )
            .add_signing_subkey();

        if let Some(pass) = &pass {
            builder = builder.set_password(Some(pass.to_owned().into()));
        }

        for email in emails {
            builder = builder.add_userid(Self::user_id(&email, name));
        }

        let (cert, sig) = builder.generate()?;
        Ok((cert, sig, pass))
    }

    /// make a "public key" ascii-armored representation of a Cert
    pub fn cert_to_armored(cert: &Cert) -> Fallible<String> {
        let v = cert.armored().to_vec().context("Cert serialize failed")?;

        Ok(String::from_utf8(v)?)
    }

    /// make a "private key" ascii-armored representation of a Cert
    pub fn priv_cert_to_armored(cert: &Cert) -> Fallible<String> {
        let mut buffer = vec![];
        {
            let headers = cert.armor_headers();
            let headers: Vec<_> = headers
                .iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let mut writer = armor::Writer::new(
                &mut buffer,
                armor::Kind::SecretKey,
                &headers,
            )
            .unwrap();

            cert.as_tsk().serialize(&mut writer)?;
            writer.finalize()?;
        }

        Ok(String::from_utf8(buffer)?)
    }

    /// make a Cert from an ascii armored key
    pub fn armored_to_cert(armored: &str) -> Fallible<Cert> {
        let cert =
            Cert::from_bytes(armored).context("Cert::from_bytes failed")?;

        Ok(cert)
    }

    /// make a Signature from an ascii armored signature
    pub fn armored_to_signature(armored: &str) -> Fallible<Signature> {
        let p = openpgp::Packet::from_bytes(armored)
            .context("Input could not be parsed")?;

        if let Packet::Signature(s) = p {
            Ok(s)
        } else {
            Err(failure::err_msg("Couldn't convert to Signature"))
        }
    }

    /// make an ascii-armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Fallible<String> {
        let mut buf = vec![];
        {
            let rev = Packet::Signature(sig.clone());

            let mut writer =
                armor::Writer::new(&mut buf, armor::Kind::Signature, &[][..])
                    .unwrap();
            rev.serialize(&mut writer)?;
            writer.finalize()?;
        }

        Ok(String::from_utf8(buf)?)
    }

    /// get expiration of cert as SystemTime
    pub fn get_expiry(cert: &Cert) -> Fallible<Option<SystemTime>> {
        let policy = StandardPolicy::new();
        let primary = cert.primary_key().with_policy(&policy, None)?;
        if let Some(duration) = primary.key_expiration_time() {
            let creation = primary.creation_time();
            Ok(creation.checked_add(duration))
        } else {
            Ok(None)
        }
    }

    /// is (possibly) revoked
    pub fn is_possibly_revoked(cert: &Cert) -> bool {
        let status = cert.revoked(&StandardPolicy::new(), None);

        status == RevocationStatus::NotAsFarAsWeKnow
    }

    /// Load Revocation Cert from file
    pub fn load_revocation_cert(
        revoc_file: Option<&PathBuf>,
    ) -> Fallible<Signature> {
        if let Some(filename) = revoc_file {
            let p = openpgp::Packet::from_file(filename)
                .context("Input could not be parsed")?;

            if let Packet::Signature(s) = p {
                return Ok(s);
            } else {
                return Err(failure::err_msg(
                    "Couldn't convert to revocation",
                ));
            }
        };
        Err(failure::err_msg("Couldn't load revocation from file"))
    }

    pub fn get_revoc_fingerprint(revoc_cert: &Signature) -> Fingerprint {
        let keyhandles = revoc_cert.get_issuers();
        let sig_fingerprints: Vec<_> = keyhandles
            .iter()
            .map(|keyhandle| {
                if let KeyHandle::Fingerprint(fp) = keyhandle {
                    Some(fp)
                } else {
                    None
                }
            })
            .filter(|fp| fp.is_some())
            .map(|fp| fp.unwrap())
            .collect();

        assert_eq!(
            sig_fingerprints.len(),
            1,
            "expected exactly one Fingerprint in revocation cert"
        );
        sig_fingerprints[0].clone()
    }

    /// user tsigns CA key
    pub fn tsign_ca(ca_cert: Cert, user: &Cert) -> Fallible<Cert> {
        let mut cert_keys = Self::get_cert_keys(&user)
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        // create a TSIG for each UserID
        for ca_uidb in ca_cert.userids() {
            for signer in &mut cert_keys {
                let builder = signature::Builder::new(
                    SignatureType::GenericCertification,
                )
                .set_trust_signature(255, 120)?;

                let tsig = ca_uidb.userid().bind(signer, &ca_cert, builder)?;
                sigs.push(tsig.into());
            }
        }

        let signed = ca_cert.merge_packets(sigs)?;

        Ok(signed)
    }

    /// add trust signature to the public key of a remote CA
    pub fn bridge_to_remote_ca(
        ca_cert: Cert,
        remote_ca_cert: Cert,
        scope_regexes: Vec<String>,
    ) -> Fallible<Cert> {
        // FIXME: do we want to support a tsig without any scope regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid
        assert_eq!(
            remote_ca_cert.userids().len(),
            1,
            "expect CA cert to have exactly one user_id"
        );
        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        let mut packets: Vec<Packet> = Vec::new();

        // create one TSIG for each regex
        for regex in scope_regexes {
            for signer in &mut cert_keys {
                let builder = signature::Builder::new(
                    SignatureType::GenericCertification,
                )
                .set_trust_signature(255, 120)?
                .set_regular_expression(regex.as_bytes())?;

                let tsig = userid.bind(signer, &remote_ca_cert, builder)?;

                packets.push(tsig.into());
            }
        }

        // FIXME: expiration?

        let signed = remote_ca_cert.merge_packets(packets)?;

        Ok(signed)
    }

    // FIXME: justus thinks this might not be supported by implementations
    pub fn bridge_revoke(
        remote_ca_cert: &Cert,
        ca_cert: &Cert,
    ) -> Fallible<(Signature, Cert)> {
        // there should be exactly one userid!
        assert_eq!(
            remote_ca_cert.userids().len(),
            1,
            "expect CA cert to have exactly one user_id"
        );
        let userid = remote_ca_cert.userids().next().unwrap().userid().clone();

        // set_trust_signature, set_regular_expression(s), expiration

        let mut cert_keys = Self::get_cert_keys(&ca_cert)?;

        // the CA should have exactly one key that can certify
        assert_eq!(cert_keys.len(), 1);

        let signer = &mut cert_keys[0];

        let mut packets: Vec<Packet> = Vec::new();

        let revocation_sig = cert::UserIDRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::Unspecified,
                b"removing OpenPGP CA bridge",
            )
            .unwrap()
            .build(signer, &remote_ca_cert, &userid, None)?;

        packets.push(revocation_sig.clone().into());

        let revoked = remote_ca_cert.clone().merge_packets(packets)?;

        Ok((revocation_sig, revoked))
    }

    /// CA signs all, or a specified list of userids of Cert
    pub fn sign_user_emails(
        ca_cert: &Cert,
        user_cert: &Cert,
        emails_filter: Option<&[&str]>,
    ) -> Fallible<Cert> {
        let policy = StandardPolicy::new();

        let mut cert_keys = Self::get_cert_keys(&ca_cert)
            .context("filtered for unencrypted secret keys above")?;

        let fp_ca = ca_cert.fingerprint();

        let mut packets: Vec<Packet> = Vec::new();

        'uid: for uid in user_cert.userids() {
            // check if this uid already has a signature by ca_cert.
            // if yes, don't add another one.
            let sigs = uid
                .clone()
                .with_policy(&policy, None)?
                .bundle()
                .certifications();
            if sigs.iter().any(|s| s.issuer_fingerprint() == Some(&fp_ca)) {
                // there is already a signature by ca_cert on this uid - skip
                continue;
            }

            for signer in &mut cert_keys {
                let userid = uid.userid();

                let uid_addr = userid
                    .email_normalized()?
                    .expect("email normalization failed");

                // did we get a filter-list for email addresses?
                if let Some(emails) = emails_filter {
                    // if so, don't process this userid if the email is
                    // not in the list
                    if !emails.contains(&uid_addr.as_str()) {
                        // don't certify this userid
                        continue 'uid;
                    }
                }

                let sig =
                    userid.certify(signer, &user_cert, None, None, None)?;

                packets.push(sig.into());

                // FIXME: complain about emails that have been specified but
                // haven't been found in the userids?
                //            panic!("Email {} not found in the key", );
            }
        }

        Ok(user_cert.clone().merge_packets(packets)?)
    }

    /// get all valid, certification capable keys with secret key material
    fn get_cert_keys(cert: &Cert) -> Fallible<Vec<KeyPair>> {
        let policy = StandardPolicy::new();
        let keys = cert
            .keys()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_certification()
            .secret();

        Ok(keys
            .filter_map(|ka| ka.key().clone().into_keypair().ok())
            .collect())
    }
}
