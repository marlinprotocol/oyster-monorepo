// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "result_outcome"))]
    pub struct ResultOutcome;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ResultOutcome;

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
        outcome -> ResultOutcome,
    }
}

diesel::table! {
    results (proposal_id) {
        #[max_length = 66]
        proposal_id -> Bpchar,
        yes -> Numeric,
        no -> Numeric,
        abstain -> Numeric,
        no_with_veto -> Numeric,
        total_voting_power -> Numeric,
        #[max_length = 66]
        tx_hash -> Bpchar,
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

diesel::joinable!(results -> proposals (proposal_id));
diesel::joinable!(votes -> proposals (proposal_id));

diesel::allow_tables_to_appear_in_same_query!(
    proposals,
    results,
    sync,
    votes,
);
