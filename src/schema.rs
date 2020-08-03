table! {
    bridges (id) {
        id -> Integer,
        email -> Text,
        scope -> Text,
        pub_key -> Text,
        cas_id -> Integer,
    }
}

table! {
    cacerts (id) {
        id -> Integer,
        cert -> Text,
        ca_id -> Integer,
    }
}

table! {
    cas (id) {
        id -> Integer,
        domainname -> Text,
    }
}

table! {
    certs (id) {
        id -> Integer,
        fingerprint -> Text,
        pub_cert -> Text,
    }
}

table! {
    certs_emails (id) {
        id -> Integer,
        cert_id -> Integer,
        email_id -> Integer,
    }
}

table! {
    emails (id) {
        id -> Integer,
        addr -> Text,
    }
}

table! {
    revocations (id) {
        id -> Integer,
        hash -> Text,
        revocation -> Text,
        published -> Bool,
        cert_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        name -> Nullable<Text>,
        ca_id -> Integer,
    }
}

table! {
    users_certs (id) {
        id -> Integer,
        user_id -> Integer,
        cert_id -> Integer,
    }
}

joinable!(bridges -> cas (cas_id));
joinable!(cacerts -> cas (ca_id));
joinable!(certs_emails -> certs (cert_id));
joinable!(certs_emails -> emails (email_id));
joinable!(revocations -> certs (cert_id));
joinable!(users -> cas (ca_id));
joinable!(users_certs -> certs (cert_id));
joinable!(users_certs -> users (user_id));

allow_tables_to_appear_in_same_query!(
    bridges,
    cacerts,
    cas,
    certs,
    certs_emails,
    emails,
    revocations,
    users,
    users_certs,
);
