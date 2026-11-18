use sqlx::postgres::PgPoolOptions;
use std::fs;
use std::path::Path;
#[allow(dead_code)]
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
        let filename = path.file_name().unwrap().to_str().unwrap();
        
        println!("Running migration: {}", filename);
        
        let sql = fs::read_to_string(&path)
            .expect(&format!("Failed to read migration file: {}", filename));

        // Split by semicolons and execute each statement separately
        let statements: Vec<&str> = sql
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for (i, statement) in statements.iter().enumerate() {
            match sqlx::query(statement).execute(&pool).await {
                Ok(_) => {
                    if i == statements.len() - 1 {
                        println!("✓ {}\n", filename);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to run migration: {}", filename);
                    eprintln!("Error on statement {}: {}\n", i + 1, e);
                    std::process::exit(1);
                }
            }
        }
    }

    println!("✅ All migrations completed successfully!");
}