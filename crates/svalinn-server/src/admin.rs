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
//!
//! **On the `println!("... {username} <{email}> ...")`-style confirmations
//! throughout this file:** CodeQL flags each one as "cleartext logging of
//! sensitive information" (nine alerts). This is a judgment call, not a
//! clear-cut false positive the way the path/token ones elsewhere in this
//! codebase are -- usernames and emails genuinely are PII, and they do get
//! printed. But the risk profile is different from a server logging a
//! secret into a shared, widely-accessible store: this is a one-shot,
//! interactively-run CLI tool, invoked by a trusted operator, printing back
//! to that same operator's own terminal an account identifier they either
//! typed in as the command's argument or already looked up to run the
//! command at all. No new exposure is created -- the operator already had
//! this information. Stripping it from the output would make the tool's
//! confirmations ("Banned so-and-so", "Created alice <alice@example.com>")
//! useless for the operator to actually verify they did what they meant to.
//! If this tool's output is ever piped into a shared/persistent log (e.g.
//! a systemd journal collected centrally), that's worth revisiting then --
//! not a reason to make the interactive case worse today.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "disposable_email.rs"]
mod disposable_email;
#[path = "email_privacy.rs"]
mod email_privacy;

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

    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    match email_privacy::init_keys(&app_env) {
        Ok(Some(warning)) => eprintln!("⚠️  {warning}"),
        Ok(None) => {}
        Err(problem) => exit_with(&problem),
    }

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
    // `who` might be a username or an email; try both, since there's no way
    // to tell from the string alone (emails are matched by blind index now,
    // not stored in plaintext -- see email_privacy.rs).
    let email_hash = email_privacy::blind_index(who);
    sqlx::query_as("SELECT id, username FROM users WHERE email_hash = $1 OR username = $2")
        .bind(email_hash)
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
    let rows: Vec<(String, Option<String>, chrono::DateTime<chrono::Utc>, Option<String>)> = sqlx::query_as(
        "SELECT username, email_encrypted, banned_at, ban_reason FROM users WHERE banned_at IS NOT NULL ORDER BY banned_at",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    if rows.is_empty() {
        println!("No banned accounts.");
    }
    for (username, email_encrypted, at, reason) in rows {
        let email = email_encrypted
            .as_deref()
            .and_then(|e| email_privacy::decrypt(e).ok())
            .unwrap_or_else(|| "?".to_string());
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
    if !email_privacy::is_plausible_format(email) {
        return Err("Enter a valid email address".into());
    }
    if disposable_email::is_disposable(email) {
        return Err("Please use a permanent email address rather than a disposable/temporary one".into());
    }
    if password.len() < 6 {
        return Err("Password must be at least 6 characters".into());
    }

    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hashing failed: {e}"))?
        .to_string();

    // An operator running this CLI is already vouching for the account, so
    // it's created pre-verified -- there's no email-sending capability here
    // to make them click a link anyway.
    sqlx::query(
        r#"
        INSERT INTO users (username, email_encrypted, email_hash, password_hash, display_name, site_role, email_verified_at)
        VALUES ($1, $2, $3, $4, $1, $5, NOW())
        "#,
    )
    .bind(username)
    .bind(email_privacy::encrypt(email))
    .bind(email_privacy::blind_index(email))
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
