use std::collections::HashSet;

use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::schema::JobEventRecord;

const MIGRATOR: Migrator = sqlx::migrate!("../framework/migrations");

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
        MIGRATOR
            .run(&self.pool)
            .await
            .context("Failed to apply migrations to the database")
    }

    pub async fn get_active_jobs(&self) -> Result<HashSet<String>> {
        let active_jobs: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT job_id
            FROM job_events
            WHERE event_name = 'Opened'

            EXCEPT

            SELECT job_id
            FROM job_events
            WHERE event_name = 'Closed'
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to query the active job ids from 'job_events' table")?;

        let mut active_jobs_set = HashSet::with_capacity(5000);
        active_jobs_set.extend(active_jobs);

        Ok(active_jobs_set)
    }

    pub async fn get_last_processed_block(&self) -> Result<i64> {
        let row = sqlx::query("SELECT last_processed_block FROM indexer_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await
            .context("Failed to query last processed block from 'indexer_state' table")?;
        Ok(row.get::<i64, _>("last_processed_block"))
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
        .context(
            "Failed to execute update query for last processed block in 'indexer state' table",
        )?;

        Ok(result.rows_affected())
    }

    pub async fn update_chain_id(&self, chain_id: String) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE indexer_state
            SET chain_id = $1, updated_at = now()
            WHERE id = 1
            "#,
        )
        .bind(chain_id)
        .execute(&self.pool)
        .await
        .context("Failed to execute update query for chain ID in 'indexer state' table")?;

        Ok(result.rows_affected())
    }

    pub async fn insert_batch(
        &self,
        records: Vec<JobEventRecord>,
        block: i64,
    ) -> Result<(u64, u64)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction for batch inserting events")?;
        let inserted_batch = self
            .insert_events(&mut tx, records.clone())
            .await
            .context("Transaction failed for batch inserting records into 'job_events' table")?;
        let updated = self.update_state(&mut tx, block).await.context(
            "Transaction failed for updating last processed block in 'indexer state' table",
        )?;
        tx.commit()
            .await
            .context("Failed to commit the batch insert transaction")?;
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

        let result = sqlx::query(
            r#"
            INSERT INTO job_events (
                job_id, event_name, event_data
            )
            SELECT * FROM UNNEST(
                $1::VARCHAR[], $2::event_name[], $3::JSONB[]
            )
            "#,
        )
        .bind(&job_ids)
        .bind(&event_names)
        .bind(&event_datas)
        .execute(&mut **tx)
        .await
        .context("Failed to execute batch insert query for job event records")?;

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
        .context("Failed to execute update query for last processed block")?;

        Ok(result.rows_affected())
    }
}
