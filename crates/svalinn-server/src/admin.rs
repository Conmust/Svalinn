//! Operator commands for accounts. Run from the repository root:
//!
//!   cargo run -p svalinn-server --bin svalinn-admin -- ban <email-or-username> [reason...]
//!   cargo run -p svalinn-server --bin svalinn-admin -- unban <email-or-username>
//!   cargo run -p svalinn-server --bin svalinn-admin -- revoke-sessions <email-or-username>
//!   cargo run -p svalinn-server --bin svalinn-admin -- list-banned
//!   cargo run -p svalinn-server --bin svalinn-admin -- create-user <username> <email> <password> [--site-owner]
//!   cargo run -p svalinn-server --bin svalinn-admin -- set-site-owner <email-or-username>
//!   cargo run -p svalinn-server --bin svalinn-admin -- remove-site-owner <email-or-username>
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
  list-banned                           Show banned accounts
  create-user <username> <email> <password> [--site-owner]
                                        Create an account (optionally a site owner)
  set-site-owner <email-or-username>    Make an account a site owner: top rank
                                        in every server it belongs to
  remove-site-owner <email-or-username> Remove the site owner role";

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
        ("create-user", Some(_)) if args.len() >= 4 => {
            let site_owner = args.iter().skip(4).any(|a| a == "--site-owner");
            create_user(&pool, &args[1], &args[2], &args[3], site_owner).await
        }
        ("set-site-owner", Some(who)) => set_site_owner(&pool, who, true).await,
        ("remove-site-owner", Some(who)) => set_site_owner(&pool, who, false).await,
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

async fn create_user(pool: &PgPool, username: &str, email: &str, password: &str, site_owner: bool) -> Result<(), String> {
    use argon2::password_hash::{PasswordHasher, SaltString};

    // Same rules as registering in the app.
    let (username, email) = (username.trim(), email.trim());
    if !(3..=50).contains(&username.len()) {
        return Err("Username must be 3-50 characters".into());
    }
    if !email.contains('@') || email.len() > 255 {
        return Err("Enter a valid email address".into());
    }
    if password.len() < 6 {
        return Err("Password must be at least 6 characters".into());
    }

    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {e}"))?
        .to_string();

    sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash, display_name, site_role)
        VALUES ($1, $2, $3, $1, $4)
        "#,
    )
    .bind(username)
    .bind(email)
    .bind(hash)
    .bind(site_owner.then_some("owner"))
    .execute(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => "That username or email is already taken".to_string(),
        e => e.to_string(),
    })?;

    println!(
        "Created {username} <{email}>{}. They can log in now.",
        if site_owner { " as a site owner" } else { "" }
    );
    Ok(())
}

async fn set_site_owner(pool: &PgPool, who: &str, owner: bool) -> Result<(), String> {
    let (id, username) = find_user(pool, who).await?;
    sqlx::query("UPDATE users SET site_role = $1 WHERE id = $2")
        .bind(owner.then_some("owner"))
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    if owner {
        println!("{username} is now a site owner: top rank in every server they belong to.");
    } else {
        println!("{username} is no longer a site owner.");
    }
    Ok(())
}
