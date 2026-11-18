use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use std::fs;
use std::path::Path;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required");

    println!("Connecting to database...");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    println!("Connected! Running migrations...\n");

    let migrations_dir = Path::new("./migrations");

    if !migrations_dir.exists() {
        eprintln!("❌ Error: migrations directory not found at {:?}", migrations_dir);
        eprintln!("Make sure you're running this from the workspace root (svalinn/ folder)");
        std::process::exit(1);
    }

    // Track which migrations have already been applied, so files that change
    // data (seeding, status resets, ...) only run once per database.
    pool.execute(
        "CREATE TABLE IF NOT EXISTS _svalinn_migrations (
            filename TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .await
    .expect("Failed to create migrations tracking table");

    let mut entries = fs::read_dir(migrations_dir)
        .expect("Failed to read migrations directory")
        .map(|e| e.expect("Failed to read entry"))
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    if entries.is_empty() {
        println!("No SQL migration files found in {:?}", migrations_dir);
        return;
    }

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let filename = path.file_name().unwrap().to_str().unwrap().to_string();

        let already_applied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _svalinn_migrations WHERE filename = $1)",
        )
        .bind(&filename)
        .fetch_one(&pool)
        .await
        .expect("Failed to read migrations tracking table");

        if already_applied {
            println!("- {} (already applied)", filename);
            continue;
        }

        println!("Running migration: {}", filename);

        let sql = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read migration file {}: {}", filename, e));

        // Run the whole file in one transaction. The file is sent as a single
        // simple query, so multi-statement files and `DO $$ ... $$` blocks
        // (which contain semicolons) work. Splitting on ';' broke those.
        let mut tx = pool.begin().await.expect("Failed to start transaction");

        if !sql.trim().is_empty() {
            if let Err(e) = (&mut *tx).execute(sql.as_str()).await {
                eprintln!("❌ Failed to run migration: {}", filename);
                eprintln!("Error: {}\n", e);
                std::process::exit(1);
            }
        }

        sqlx::query("INSERT INTO _svalinn_migrations (filename) VALUES ($1)")
            .bind(&filename)
            .execute(&mut *tx)
            .await
            .expect("Failed to record migration");

        tx.commit().await.expect("Failed to commit migration");
        println!("✓ {}\n", filename);
    }

    println!("✅ All migrations completed successfully!");
}
