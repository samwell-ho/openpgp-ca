table! {
    bridges (id) {
        id -> Integer,
        name -> Text,
        pub_key -> Text,
        cas_id -> Integer,
    }
}

table! {
    ca_certs (id) {
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
    certs_emails (id) {
        id -> Integer,
        user_cert_id -> Integer,
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
    prefs (id) {
        id -> Integer,
    }
}

table! {
    revocations (id) {
        id -> Integer,
        revocation -> Text,
        user_cert_id -> Integer,
    }
}

table! {
    user_certs (id) {
        id -> Integer,
        pub_cert -> Text,
        fingerprint -> Text,
        user_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        name -> Nullable<Text>,
        ca_id -> Integer,
    }
}

joinable!(bridges -> cas (cas_id));
joinable!(ca_certs -> cas (ca_id));
joinable!(certs_emails -> emails (email_id));
joinable!(certs_emails -> user_certs (user_cert_id));
joinable!(revocations -> user_certs (user_cert_id));
joinable!(user_certs -> users (user_id));
joinable!(users -> cas (ca_id));

allow_tables_to_appear_in_same_query!(
    bridges,
    ca_certs,
    cas,
    certs_emails,
    emails,
    prefs,
    revocations,
    user_certs,
    users,
);
