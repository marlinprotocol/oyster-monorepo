// @generated automatically by Diesel CLI.

diesel::table! {
    proposals (id) {
        #[max_length = 66]
        id -> Bpchar,
        #[max_length = 42]
        proposer -> Bpchar,
        nonce -> Numeric,
        title -> Text,
        description -> Text,
        #[max_length = 66]
        tx_hash -> Bpchar,
        executed -> Bool,
        proposal_created_at -> Numeric,
        proposal_end_time -> Numeric,
        voting_start_time -> Numeric,
        voting_end_time -> Numeric,
    }
}

diesel::table! {
    sync (block) {
        block -> Int8,
    }
}

diesel::table! {
    votes (proposal_id, voter) {
        #[max_length = 66]
        proposal_id -> Bpchar,
        #[max_length = 42]
        voter -> Bpchar,
        vote -> Numeric,
    }
}

diesel::joinable!(votes -> proposals (proposal_id));

diesel::allow_tables_to_appear_in_same_query!(
    proposals,
    sync,
    votes,
);
