//! Operator commands for accounts. Run from the repository root:
//!
//!   cargo run -p svalinn-server --bin svalinn-admin -- ban <email-or-username> [reason...]
//!   cargo run -p svalinn-server --bin svalinn-admin -- unban <email-or-username>
//!   cargo run -p svalinn-server --bin svalinn-admin -- revoke-sessions <email-or-username>
//!   cargo run -p svalinn-server --bin svalinn-admin -- list-banned
//!
//! Banning takes effect immediately: the database notifies running servers,
//! which close the user's connections, and every request checks the ban.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const USAGE: &str = "\
Usage: svalinn-admin <command>

  ban <email-or-username> [reason...]   Ban an account and end all its sessions
  unban <email-or-username>             Lift a ban (the user logs in again)
  revoke-sessions <email-or-username>   Log the account out everywhere
  list-banned                           Show banned accounts";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        exit_with(USAGE);
    };

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| exit_with("DATABASE_URL is required"));
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| exit_with(&format!("Failed to connect to database: {e}")));

    let result = match (command, args.get(1)) {
        ("ban", Some(who)) => {
            let reason = args[2..].join(" ");
            ban(&pool, who, (!reason.trim().is_empty()).then(|| reason.trim().to_string())).await
        }
        ("unban", Some(who)) => unban(&pool, who).await,
        ("revoke-sessions", Some(who)) => revoke_sessions(&pool, who).await,
        ("list-banned", _) => list_banned(&pool).await,
        _ => Err(USAGE.to_string()),
    };

    if let Err(message) = result {
        exit_with(&message);
    }
}

fn exit_with(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

async fn find_user(pool: &PgPool, who: &str) -> Result<(Uuid, String), String> {
    sqlx::query_as("SELECT id, username FROM users WHERE email = $1 OR username = $1")
        .bind(who)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("No account with email or username {who:?}"))
}

async fn ban(pool: &PgPool, who: &str, reason: Option<String>) -> Result<(), String> {
    let (id, username) = find_user(pool, who).await?;
    // The users_banned trigger ends every session and notifies running servers.
    let newly_banned: bool = sqlx::query_scalar(
        r#"
        WITH before AS (SELECT banned_at IS NULL AS was_unbanned FROM users WHERE id = $1)
        UPDATE users SET banned_at = COALESCE(banned_at, NOW()), ban_reason = $2
        WHERE id = $1
        RETURNING (SELECT was_unbanned FROM before)
        "#,
    )
    .bind(id)
    .bind(&reason)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    if newly_banned {
        println!("Banned {username}. Their sessions are revoked and open connections closed.");
    } else {
        println!("{username} was already banned; reason updated.");
    }
    Ok(())
}

async fn unban(pool: &PgPool, who: &str) -> Result<(), String> {
    let (id, username) = find_user(pool, who).await?;
    let changed = sqlx::query("UPDATE users SET banned_at = NULL, ban_reason = NULL WHERE id = $1 AND banned_at IS NOT NULL")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?
        .rows_affected();

    if changed == 0 {
        println!("{username} wasn't banned.");
    } else {
        println!("Unbanned {username}. They can log in again.");
    }
    Ok(())
}

async fn revoke_sessions(pool: &PgPool, who: &str) -> Result<(), String> {
    let (id, username) = find_user(pool, who).await?;
    // The refresh_tokens_revoked trigger notifies running servers.
    let revoked = sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?
        .rows_affected();
    println!("Ended {revoked} session(s) for {username}.");
    Ok(())
}

async fn list_banned(pool: &PgPool) -> Result<(), String> {
    let rows: Vec<(String, String, chrono::DateTime<chrono::Utc>, Option<String>)> = sqlx::query_as(
        "SELECT username, email, banned_at, ban_reason FROM users WHERE banned_at IS NOT NULL ORDER BY banned_at",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    if rows.is_empty() {
        println!("No banned accounts.");
    }
    for (username, email, at, reason) in rows {
        println!("{username} <{email}>  banned {}  {}", at.format("%Y-%m-%d %H:%M UTC"), reason.unwrap_or_default());
    }
    Ok(())
}
