use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::time::timeout;

use crate::schema::JobEventRecord;

const MIGRATOR: Migrator = sqlx::migrate!("../framework/migrations");

const UPDATE_INDEXER_STATE_FULL: &str = r#"
    UPDATE indexer_state
    SET chain_id = $1,
        extra_decimals = $2,
        last_processed_block = $3,
        updated_at = now()
    WHERE id = 1
"#;
const UPDATE_INDEXER_STATE_PARTIAL: &str = r#"
    UPDATE indexer_state
    SET chain_id = $1,
        extra_decimals = $2,
        updated_at = now()
    WHERE id = 1
"#;
const FETCH_LAST_PROCESSED_BLOCK: &str = r#"
    SELECT last_processed_block 
    FROM indexer_state 
    WHERE id = 1
"#;
const FETCH_ACTIVE_JOBS: &str = r#"
    SELECT job_id
    FROM job_events
    WHERE event_name = 'Opened'
    EXCEPT
    SELECT job_id
    FROM job_events
    WHERE event_name = 'Closed'
"#;
const BATCH_INSERT_JOB_EVENTS: &str = r#"
    INSERT INTO job_events(
        job_id, event_name, event_data
    )
    SELECT * FROM UNNEST(
        $1::VARCHAR[], $2::event_name[], $3::JSONB[]
    )
"#;
const UPDATE_LAST_PROCESSED_BLOCK: &str = r#"
    UPDATE indexer_state
    SET last_processed_block = $1, 
        updated_at = now()
    WHERE id = 1
"#;

#[derive(Clone, Debug)]
pub struct Repository {
    pub pool: PgPool,
}

impl Repository {
    pub async fn new(db_url: String) -> Result<Self> {
        // Create an async connection pool
        let pool = timeout(
            Duration::from_secs(5),
            PgPoolOptions::new()
                .max_connections(5)
                .acquire_timeout(Duration::from_secs(5))
                .idle_timeout(Duration::from_secs(300))
                .max_lifetime(Duration::from_secs(1800))
                .connect(&db_url),
        )
        .await
        .context("Timed out connecting to the DATABASE_URL")?
        .context("Failed to connect to the DATABASE_URL")?;

        Ok(Self { pool })
    }

    pub async fn apply_migrations(&self) -> Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("Failed to apply migrations to the database")
    }

    pub async fn update_indexer_state(
        &self,
        chain_id: String,
        extra_decimals: i64,
        start_block: Option<i64>,
    ) -> Result<u64> {
        let query = match start_block {
            Some(block) => sqlx::query(UPDATE_INDEXER_STATE_FULL)
                .bind(chain_id)
                .bind(extra_decimals)
                .bind(block - 1),
            None => sqlx::query(UPDATE_INDEXER_STATE_PARTIAL)
                .bind(chain_id)
                .bind(extra_decimals),
        };

        let result = query
            .execute(&self.pool)
            .await
            .context("Failed to execute update record query in indexer_state table")?;

        Ok(result.rows_affected())
    }

    pub async fn get_last_processed_block(&self) -> Result<i64> {
        let row = sqlx::query(FETCH_LAST_PROCESSED_BLOCK)
            .fetch_one(&self.pool)
            .await
            .context("Failed to query last processed block from indexer_state table")?;

        row.try_get::<i64, _>("last_processed_block")
            .context("Failed to find last processed block in indexer_state table record")
    }

    pub async fn get_active_jobs(&self) -> Result<HashSet<String>> {
        let active_jobs: Vec<String> = sqlx::query_scalar(FETCH_ACTIVE_JOBS)
            .fetch_all(&self.pool)
            .await
            .context("Failed to query the active job ids from job_events table")?;

        let mut active_jobs_set = HashSet::new();
        active_jobs_set.extend(active_jobs);

        Ok(active_jobs_set)
    }

    pub async fn insert_batch(&self, records: &[JobEventRecord], block: i64) -> Result<(u64, u64)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction for inserting events batch into DB")?;
        let inserted_batch = self
            .insert_events(&mut tx, records.to_owned())
            .await
            .context("Transaction failed for batch inserting records into job_events table")?;
        let updated = self
            .update_last_processed_block(&mut tx, block)
            .await
            .context(
                "Transaction failed for updating last processed block in indexer state table",
            )?;
        tx.commit()
            .await
            .context("Failed to commit the batch insert transaction to DB")?;
        Ok((inserted_batch, updated))
    }

    async fn insert_events(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        records: Vec<JobEventRecord>,
    ) -> Result<u64> {
        if records.is_empty() {
            return Ok(0);
        }

        let mut job_ids = Vec::with_capacity(records.len());
        let mut event_names = Vec::with_capacity(records.len());
        let mut event_datas = Vec::with_capacity(records.len());

        for record in records {
            job_ids.push(record.job_id);
            event_names.push(record.event_name);
            event_datas.push(record.event_data);
        }

        let result = sqlx::query(BATCH_INSERT_JOB_EVENTS)
            .bind(&job_ids)
            .bind(&event_names)
            .bind(&event_datas)
            .execute(&mut **tx)
            .await
            .context(
                "Failed to execute batch insert query for event records in job_events table",
            )?;

        Ok(result.rows_affected())
    }

    async fn update_last_processed_block(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        block: i64,
    ) -> Result<u64> {
        let result = sqlx::query(UPDATE_LAST_PROCESSED_BLOCK)
            .bind(block)
            .execute(&mut **tx)
            .await
            .context(
                "Failed to execute update query for last processed block in indexer_state table",
            )?;

        Ok(result.rows_affected())
    }
}
