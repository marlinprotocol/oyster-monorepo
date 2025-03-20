// @generated automatically by Diesel CLI.

diesel::table! {
    jobs (id) {
        #[max_length = 66]
        id -> Bpchar,
        metadata -> Text,
        #[max_length = 42]
        owner -> Bpchar,
        #[max_length = 42]
        provider -> Bpchar,
        rate -> Nullable<Numeric>,
        balance -> Nullable<Numeric>,
        last_settled -> Nullable<Timestamp>,
        created -> Nullable<Timestamp>,
        is_closed -> Bool,
        usdc_balance -> Nullable<Numeric>,
        credits_balance -> Nullable<Numeric>,
    }
}

diesel::table! {
    providers (id) {
        #[max_length = 42]
        id -> Bpchar,
        cp -> Text,
        is_active -> Bool,
    }
}

diesel::table! {
    revise_rate_requests (id) {
        #[max_length = 66]
        id -> Bpchar,
        value -> Numeric,
        updates_at -> Timestamp,
    }
}

diesel::table! {
    sync (block) {
        block -> Int8,
    }
}

diesel::table! {
    transactions (block, idx) {
        block -> Int8,
        idx -> Int8,
        #[max_length = 66]
        tx_hash -> Bpchar,
        #[max_length = 66]
        job -> Bpchar,
        amount -> Numeric,
        is_deposit -> Bool,
        is_usdc -> Bool,
    }
}

diesel::joinable!(revise_rate_requests -> jobs (id));
diesel::joinable!(transactions -> jobs (job));

diesel::allow_tables_to_appear_in_same_query!(
    jobs,
    providers,
    revise_rate_requests,
    sync,
    transactions,
);
