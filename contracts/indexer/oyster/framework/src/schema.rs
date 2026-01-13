// @generated automatically by Diesel CLI.

diesel::table! {
    jobs (id) {
        #[max_length = 66]
        id -> Bpchar,
        metadata -> Text,
        #[max_length = 66]
        owner -> Bpchar,
        #[max_length = 66]
        provider -> Bpchar,
        rate -> Numeric,
        balance -> Numeric,
        last_settled -> Timestamp,
        created -> Timestamp,
        is_closed -> Bool,
        end_epoch -> Numeric,
    }
}

diesel::table! {
    providers (id) {
        #[max_length = 66]
        id -> Bpchar,
        cp -> Text,
        block -> Int8,
        #[max_length = 66]
        tx_hash -> Bpchar,
        is_active -> Bool,
    }
}

diesel::table! {
    rate_revisions (job_id, block) {
        #[max_length = 66]
        job_id -> Bpchar,
        value -> Numeric,
        block -> Int8,
        timestamp -> Numeric,
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
    settlement_history (id, block) {
        #[max_length = 66]
        id -> Bpchar,
        amount -> Numeric,
        timestamp -> Numeric,
        block -> Int8,
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
    }
}

diesel::joinable!(rate_revisions -> jobs (job_id));
diesel::joinable!(revise_rate_requests -> jobs (id));
diesel::joinable!(settlement_history -> jobs (id));
diesel::joinable!(transactions -> jobs (job));

diesel::allow_tables_to_appear_in_same_query!(
    jobs,
    providers,
    rate_revisions,
    revise_rate_requests,
    settlement_history,
    sync,
    transactions,
);
