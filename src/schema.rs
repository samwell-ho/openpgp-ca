table! {
    cas (id) {
        id -> Integer,
        name -> Text,
        email -> Text,
        ca_key -> Text,
        revoc_cert -> Text,
    }
}

table! {
    emails (id) {
        id -> Integer,
        addr -> Text,
        user_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        name -> Nullable<Text>,
        pub_key -> Text,
        revoc_cert -> Nullable<Text>,
        cas_id -> Integer,
    }
}

joinable!(emails -> users (user_id));
joinable!(users -> cas (cas_id));

allow_tables_to_appear_in_same_query!(
    cas,
    emails,
    users,
);
