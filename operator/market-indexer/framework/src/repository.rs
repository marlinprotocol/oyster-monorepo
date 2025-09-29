use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::schema::JobEventRecord;

const MIGRATION_PATH: &str = "../framework/migrations";

#[derive(Clone, Debug)]
pub struct Repository {
    pub pool: PgPool,
}

impl Repository {
    pub async fn new(db_url: String) -> Result<Self> {
        // Create an async connection pool
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .context("Failed to connect to the DATABASE_URL")?;

        Ok(Self { pool })
    }

    pub async fn apply_migrations(&self) -> Result<()> {
        let migrator = Migrator::new(Path::new(MIGRATION_PATH))
            .await
            .context("Failed to initialize the migrator")?;
        migrator
            .run(&self.pool)
            .await
            .context("Failed to apply migrations to the database")
    }

    pub async fn get_active_jobs(&self) -> Result<HashSet<String>> {
        let active_jobs: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT job_id
            FROM job_events
            WHERE event_name = 'JobOpened'

            EXCEPT

            SELECT job_id
            FROM job_events
            WHERE event_name = 'JobClosed'
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch the active job ids")?;

        let mut active_jobs_set = HashSet::with_capacity(5000);
        active_jobs_set.extend(active_jobs);

        Ok(active_jobs_set)
    }

    pub async fn get_last_processed_block(&self) -> Result<i64> {
        let row = sqlx::query("SELECT last_processed_block FROM indexer_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await
            .context("Failed to fetch 'last_processed_block'")?;
        Ok(row.get::<i64, _>("last_processed_block"))
    }

    pub async fn insert_batch(
        &self,
        records: Vec<JobEventRecord>,
        block: i64,
    ) -> Result<(u64, u64)> {
        let mut tx = self.pool.begin().await?;
        let inserted_batch = self.insert_events(&mut tx, records.clone()).await?;
        let updated = self.update_state(&mut tx, block).await?;
        tx.commit().await?;
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

        let mut block_ids = Vec::with_capacity(records.len());
        let mut tx_hashes = Vec::with_capacity(records.len());
        let mut event_seqs = Vec::with_capacity(records.len());
        let mut block_timestamps = Vec::with_capacity(records.len());
        let mut senders = Vec::with_capacity(records.len());
        let mut event_names = Vec::with_capacity(records.len());
        let mut event_datas = Vec::with_capacity(records.len());
        let mut job_ids = Vec::with_capacity(records.len());

        for record in records {
            block_ids.push(record.block_id);
            tx_hashes.push(record.tx_hash);
            event_seqs.push(record.event_seq);
            block_timestamps.push(record.block_timestamp);
            senders.push(record.sender);
            event_names.push(record.event_name);
            event_datas.push(record.event_data);
            job_ids.push(record.job_id);
        }

        let result = sqlx::query(
            r#"
            INSERT INTO job_events (
                block_id, tx_hash, event_seq,
                block_timestamp, sender, event_name,
                event_data, job_id
            )
            SELECT * FROM UNNEST(
                $1::BIGINT[], $2::VARCHAR[], $3::BIGINT[], $4::TIMESTAMPTZ[], $5::VARCHAR[],
                $6::VARCHAR[], $7::JSONB[], $8::VARCHAR[]
            )
            "#,
        )
        .bind(&block_ids)
        .bind(&tx_hashes)
        .bind(&event_seqs)
        .bind(&block_timestamps)
        .bind(&senders)
        .bind(&event_names)
        .bind(&event_datas)
        .bind(&job_ids)
        .execute(&mut **tx)
        .await
        .context("Failed to batch insert job events")?;

        Ok(result.rows_affected())
    }

    async fn update_state(&self, tx: &mut Transaction<'_, Postgres>, block: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE indexer_state
            SET last_processed_block = $1, updated_at = now()
            WHERE id = 1
            "#,
        )
        .bind(block)
        .execute(&mut **tx)
        .await
        .context("Failed to update indexer state")?;

        Ok(result.rows_affected())
    }

    pub async fn update_state_atomic(&self, block: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE indexer_state
            SET last_processed_block = $1, updated_at = now()
            WHERE id = 1
            "#,
        )
        .bind(block)
        .execute(&self.pool)
        .await
        .context("Failed to update indexer state")?;

        Ok(result.rows_affected())
    }
}
