use diesel::{Connection, PgConnection, RunQueryDsl};
use diesel_migrations::FileBasedMigrations;
use diesel_migrations::MigrationHarness;

fn id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ID: AtomicUsize = AtomicUsize::new(0);
    ID.fetch_add(1, Ordering::SeqCst)
}

pub struct TestDb {
    pub name: String,
    pub conn: PgConnection,
}

impl TestDb {
    pub fn new() -> Self {
        dotenvy::dotenv().ok();

        let db_name = format!("oyster_indexer_test_{}", id().to_string());
        let admin_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let test_url = admin_url[..=admin_url.rfind('/').unwrap()].to_owned() + &db_name;

        // Create the database
        let mut admin_conn =
            PgConnection::establish(&admin_url).expect("Failed to connect to PostgreSQL admin");
        diesel::sql_query(&format!("CREATE DATABASE {}", db_name))
            .execute(&mut admin_conn)
            .expect("Failed to create test database");

        // Set up the connection
        let test_conn =
            PgConnection::establish(&test_url).expect("Failed to connect to PostgreSQL test");

        let mut db = TestDb {
            name: db_name,
            conn: test_conn,
        };

        let migrations = FileBasedMigrations::find_migrations_directory().unwrap();
        db.conn.run_pending_migrations(migrations).unwrap();

        db
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        dotenvy::dotenv().ok();

        let admin_url = std::env::var("TEST_DATABASE_URL").unwrap();

        self.conn = PgConnection::establish(&admin_url)
            .expect("Failed to connect to PostgreSQL for cleanup");

        diesel::sql_query(&format!("DROP DATABASE {}", self.name))
            .execute(&mut self.conn)
            .expect("Failed to drop test database");
    }
}
