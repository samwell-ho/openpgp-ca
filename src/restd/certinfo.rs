use chrono::{DateTime, Utc};
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

/// Human-readable, factual information about an OpenPGP certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub fingerprint: String,

    pub user_ids: Vec<String>,

    pub primary_creation_time: DateTime<Utc>,
    // pk_algo: String,

    // pk_size: usize,

    // subkeys: Vec<SubkeyInfo>,

    // revocation status
}

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
