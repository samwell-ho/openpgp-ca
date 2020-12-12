// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;

use openpgp::Cert;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::packet::UserID;
use std::convert::TryFrom;

pub fn is_email_in_domain(email: &str, domain: &str) -> Result<bool> {
    let split: Vec<_> = email.split('@').collect();

    if split.len() != 2 {
        Err(anyhow::anyhow!("ERROR: unexpected email syntax {}", email))
    } else {
        Ok(split[1] == domain)
    }
}

/// takes a domain name and a list of email addresses, and checks which of
/// these addresses are "internal" to the domain.
///
/// returns two lists of email addresses: (internal, external)
pub fn split_emails(
    domain: &str,
    emails: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let mut int: Vec<String> = Vec::new();
    let mut ext: Vec<String> = Vec::new();

    for email in emails {
        if is_email_in_domain(email, domain)? {
            int.push(email.to_string());
        } else {
            ext.push(email.to_string());
        }
    }

    Ok((int, ext))
}

/// Make a copy of Cert, but without the User ID user_id.
/// See https://docs.sequoia-pgp.org/sequoia_openpgp/cert/struct.Cert.html#filtering-certificates
pub fn user_id_filter(cert: &Cert, user_id: &UserID) -> Result<Cert> {
    // FIXME use:
    // https://docs.sequoia-pgp.org/sequoia_openpgp/cert/struct.Cert.html#method.retain_userids

    // Iterate over all of the Cert components, pushing packets we
    // want to keep into the accumulator.
    let mut acc = Vec::new();

    // Primary key and related signatures.
    let c = cert.primary_key();
    acc.push(c.key().clone().into());
    for s in c.self_signatures() {
        acc.push(s.clone().into())
    }
    for s in c.certifications() {
        acc.push(s.clone().into())
    }
    for s in c.self_revocations() {
        acc.push(s.clone().into())
    }
    for s in c.other_revocations() {
        acc.push(s.clone().into())
    }

    // UserIDs and related signatures.
    for c in cert.userids() {
        if c.userid() != user_id {
            acc.push(c.userid().clone().into());
            for s in c.self_signatures() {
                acc.push(s.clone().into())
            }
            for s in c.certifications() {
                acc.push(s.clone().into())
            }
            for s in c.self_revocations() {
                acc.push(s.clone().into())
            }
            for s in c.other_revocations() {
                acc.push(s.clone().into())
            }
        }
    }

    // UserAttributes and related signatures.
    for c in cert.user_attributes() {
        acc.push(c.user_attribute().clone().into());
        for s in c.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Subkeys and related signatures.
    for c in cert.keys().subkeys() {
        acc.push(c.key().clone().into());
        for s in c.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Unknown components and related signatures.
    for c in cert.unknowns() {
        acc.push(c.unknown().clone().into());
        for s in c.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in c.certifications() {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in c.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // Any signatures that we could not associate with a component.
    for s in cert.bad_signatures() {
        acc.push(s.clone().into())
    }

    // Finally, parse into Cert.
    Cert::try_from(acc)
}

#[test]
fn test_split() {
    let (int, ext) = split_emails(
        "fsfe.org",
        &[
            "foo@fsfe.org".to_string(),
            "bar@fsfe.org".to_string(),
            "foo@gmail.com".to_string(),
            "bar@gmail.com".to_string(),
        ],
    )
    .unwrap();

    assert_eq!(
        int,
        vec!["foo@fsfe.org".to_string(), "bar@fsfe.org".to_string(),],
    );
    assert_eq!(
        ext,
        vec!["foo@gmail.com".to_string(), "bar@gmail.com".to_string(),],
    );
}
