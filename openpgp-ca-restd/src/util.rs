// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Result;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Cert;

pub fn is_email_in_domain(email: &str, domain: &str) -> Result<bool> {
    let split: Vec<_> = email.split('@').collect();

    if split.len() != 2 {
        Err(anyhow::anyhow!(
            "is_email_in_domain: unexpected email syntax {}",
            email
        ))
    } else {
        Ok(split[1] == domain)
    }
}

/// takes a domain name and a list of email addresses, and checks which of
/// these addresses are "internal" to the domain.
///
/// returns two lists of email addresses: (internal, external)
pub fn split_emails(domain: &str, emails: &[String]) -> Result<(Vec<String>, Vec<String>)> {
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

/// Remove the User ID "filter" from a Cert
pub fn user_id_filter(cert: Cert, filter: &UserID) -> Cert {
    cert.retain_userids(|ua| ua.userid() != filter)
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
