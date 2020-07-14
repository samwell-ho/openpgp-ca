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
    certs_emails (id) {
        id -> Integer,
        usercert_id -> Integer,
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
        usercert_id -> Integer,
    }
}

table! {
    usercerts (id) {
        id -> Integer,
        updates_cert_id -> Nullable<Integer>,
        name -> Nullable<Text>,
        pub_cert -> Text,
        fingerprint -> Text,
        ca_id -> Integer,
    }
}

joinable!(bridges -> cas (cas_id));
joinable!(cacerts -> cas (ca_id));
joinable!(certs_emails -> emails (email_id));
joinable!(certs_emails -> usercerts (usercert_id));
joinable!(revocations -> usercerts (usercert_id));
joinable!(usercerts -> cas (ca_id));

allow_tables_to_appear_in_same_query!(
    bridges,
    cacerts,
    cas,
    certs_emails,
    emails,
    revocations,
    usercerts,
);
