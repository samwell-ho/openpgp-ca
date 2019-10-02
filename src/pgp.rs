// Copyright 2019 Heiko Schaefer heiko@schaefer.name
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

use openpgp::Packet;
use openpgp::TPK;
use openpgp::armor;
use openpgp::constants::{SignatureType, HashAlgorithm, ReasonForRevocation};
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::packet::signature::Builder;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::tpk;

use failure::{self, ResultExt};

pub type Result<T> = ::std::result::Result<T, failure::Error>;

pub struct Pgp {}

impl Pgp {
    /// Generate an encryption- and signing-capable key.
    fn generate(emails: Option<&[&str]>) -> Result<(TPK, Signature)> {
        let (tpk, revocation) = tpk::TPKBuilder::new()
            .add_encryption_subkey()
            .add_signing_subkey()
            .generate()?;

        if let Some(emails) = emails {
            let mut packets = Vec::new();
            let mut signer = tpk.primary().clone().into_keypair()?;

            for &email in emails {
                let userid = UserID::from(email);
                packets.push(userid.clone().into());

                let builder = Builder::new(SignatureType::PositiveCertificate);
                let binding =
                    userid.bind(&mut signer, &tpk, builder, None, None)?;

                packets.push(binding.into());
            }

            Ok((tpk.merge_packets(packets)?, revocation))
        } else {
            Ok((tpk, revocation))
        }
    }

    /// make a "public key" ascii-armored representation of a TPK
    pub fn tpk_to_armored(certified: &TPK) -> Result<String> {
        let mut v = Vec::new();
        tpk::armor::Encoder::new(&certified).serialize(&mut v)
            .context("tpk serialize failed")?;

        Ok(String::from_utf8(v)?.to_string())
    }

    /// make a "private key" ascii-armored representation of a TPK
    pub fn priv_tpk_to_armored(tpk: &TPK) -> Result<String> {
        let mut buffer = std::io::Cursor::new(vec![]);
        {
            let mut writer =
                armor::Writer::new(&mut buffer,
                                   armor::Kind::SecretKey,
                                   &[][..]).unwrap();

            tpk.as_tsk().serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buffer.get_ref().to_vec())?.to_string())
    }

    /// make a TPK from an ascii armored key
    pub fn armored_to_tpk(armored: &str) -> TPK {
        TPK::from_bytes(armored.as_bytes()).unwrap()
    }

    /// make an ascii-armored representation of a Signature
    pub fn sig_to_armored(sig: &Signature) -> Result<String> {
        // maybe use:
        // https://docs.sequoia-pgp.org/sequoia_openpgp/serialize/trait.Serialize.html#method.export

        let mut buf = std::io::Cursor::new(vec![]);
        {
            let mut writer =
                armor::Writer::new(&mut buf,
                                   armor::Kind::Signature,
                                   &[][..]).unwrap();
            sig.serialize(&mut writer)?;
        }

        Ok(String::from_utf8(buf.get_ref().to_vec())?.to_string())
    }

    /// make a private CA key
    pub fn make_private_ca_key(ca_uids: &[&str])
                               -> Result<(TPK, Signature)> {
        Pgp::generate(Some(&ca_uids.to_vec()))
    }

    /// user tsigns CA key
    pub fn tsign_ca(ca_key: &TPK, user: &TPK) -> Result<TPK> {
        let mut signer = user.primary().clone().into_keypair()
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        // FIXME: assert there is exactly one userid?

        // create TSIG
        for ca_uidb in ca_key.userids() {
            let builder = Builder::new(SignatureType::GenericCertificate)
                .set_trust_signature(255, 120)?;

            let tsig = ca_uidb.userid().bind(&mut signer,
                                             ca_key,
                                             builder,
                                             None, None)?;

            sigs.push(tsig.into());
        }

        let signed = ca_key.clone().merge_packets(sigs)?;

        Ok(signed)
    }

    /// add trust signature to the public key of a remote CA
    pub fn bridge_to_remote_ca(ca_key: &TPK,
                               remote_ca_key: &TPK,
                               regexes: Option<&[&str]>) -> Result<TPK> {

        // FIXME: do we want to support a tsig without any regex?
        // -> or force users to explicitly set a catchall regex, then.

        // there should be exactly one userid!
        let userid = remote_ca_key.userids().next().unwrap().userid();

        // set_trust_signature + set_regular_expression(s)

        let mut signer = ca_key.primary().clone().into_keypair()?;

        let remote_pubkey = remote_ca_key.primary();

        let mut packets: Vec<Packet> = Vec::new();

        // create one TSIG for each regex
        if let Some(regexes) = regexes {
            for &regex in regexes {
                let tsig = Builder::new(SignatureType::GenericCertificate)
                    .set_trust_signature(255, 120)?
                    .set_regular_expression(regex.as_bytes())?
                    .sign_userid_binding(&mut signer,
                                         remote_pubkey,
                                         userid,
                                         HashAlgorithm::SHA512)?;

                packets.push(tsig.into());
            }
        }

        // FIXME: expiration?

        let signed = remote_ca_key.clone().merge_packets(packets)?;

        Ok(signed)
    }

    pub fn bridge_revoke(remote_ca_key: &TPK, ca_key: &TPK)
                         -> Result<(Signature, TPK)> {
        // there should be exactly one userid!
        let userid = remote_ca_key.userids().next().unwrap().userid();

        // set_trust_signature, set_regular_expression(s), expiration

        let mut signer = ca_key.primary().clone().into_keypair()?;

        let mut packets: Vec<Packet> = Vec::new();

        // create revocation sig
        let revocation_sig = userid
            .revoke(&mut signer, &remote_ca_key,
                    ReasonForRevocation::Unspecified,
                    b"removing OpenPGP CA bridge", None, None)?;

        packets.push(revocation_sig.clone().into());

        let revoked = remote_ca_key.clone().merge_packets(packets)?;

        Ok((revocation_sig, revoked))
    }

    /// sign all userids of TPK with CA TPK
    pub fn sign_user(ca_key: &TPK, user: &TPK) -> Result<TPK> {

        // sign tpk with CA key
        let mut signer = ca_key.primary().clone().into_keypair()
            .context("filtered for unencrypted secret keys above")?;

        let mut sigs = Vec::new();

        for uidb in user.userids() {
            let uid = uidb.userid();

            let sig = uid.certify(&mut signer, &user, None, None, None)?;

            sigs.push(sig.into());
        }

        let certified = user.clone().merge_packets(sigs)?;

        Ok(certified)
    }

    pub fn sign_user_emails(ca_key: &TPK, user_key: &TPK, emails: &[&str]) -> Result<TPK> {
        let mut ca_keypair = ca_key.primary().clone().into_keypair()?;

        let mut packets: Vec<Packet> = Vec::new();

        for uid in user_key.userids() {
            let userid = uid.userid();
            let uid_addr = userid.address_normalized()?.unwrap();

            // Sign this userid if email has been given for this import call
            if emails.contains(&uid_addr.as_str()) {
                // certify this userid
                let cert = userid.certify(&mut ca_keypair,
                                          &user_key,
                                          SignatureType::PositiveCertificate,
                                          None, None)?;

                packets.push(cert.into());
            }

            // FIXME: complain about emails that have been specified but
            // haven't been found in the userids
//            panic!("Email {} not found in the key", );
        }

        let result = user_key.clone().merge_packets(packets)?;
        Ok(result)
    }

    /// make a user TPK with "emails" as UIDs (all UIDs get signed)
    pub fn make_user(emails: Option<&[&str]>) -> Result<(TPK, Signature)> {
        // make user key
        let (user_tpk, revocation) = Pgp::generate(emails).unwrap();

        let mut keypair = user_tpk.primary().clone().into_keypair()?;
        assert_eq!(user_tpk.userids().len(), emails.clone().unwrap().len());

        let mut packets = Vec::new();

        if let Some(e) = emails {
            for &uid in e {
                // Generate userid ..
                let userid = UserID::from(uid);
                packets.push(userid.clone().into());

                // .. and a binding signature.
                let builder =
                    Builder::new(SignatureType::PositiveCertificate);
                let binding = userid.bind(&mut keypair,
                                          &user_tpk,
                                          builder,
                                          None, None)?;

                packets.push(binding.into());
            }
        }

        // Now merge the userid and binding signature into the TPK.
        let user_tpk = user_tpk.merge_packets(packets)?;

        // done
        Ok((user_tpk, revocation))
    }
}