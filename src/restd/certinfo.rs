use chrono::{DateTime, Utc};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

// check: sq dump for various keys

/// Human-readable information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize)]
pub struct CertInfo {
    fingerprint: String,

    user_ids: Vec<String>,

    primary_creation_time: DateTime<Utc>,
    // pk_algo: String,
    // pk_size: usize,
    // subkeys: Vec<SubkeyInfo>,
    // revocation status
}

// #[derive(Debug, Serialize, Deserialize)]
// struct SubkeyInfo {}

impl From<&Cert> for CertInfo {
    fn from(cert: &Cert) -> Self {
        let emails = cert
            .userids()
            .filter_map(|uid| {
                uid.email().expect("ERROR while converting user_id")
            })
            .collect();

        CertInfo {
            fingerprint: cert.fingerprint().to_hex(),
            user_ids: emails,
            primary_creation_time: cert.primary_key().creation_time().into(),
        }
    }
}
