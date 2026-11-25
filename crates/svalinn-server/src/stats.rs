//! Background job that keeps `user_count_snapshots` current.
//!
//! This exists purely to back a public "how many people have signed up"
//! chart. It only ever writes a single aggregate count per day -- it never
//! touches, logs, or joins against anything that identifies a user. The
//! live count (`routes::stats::get_user_count`) is computed fresh on every
//! request straight from `users`, so a visitor never sees anything stale;
//! this job only maintains the day-by-day history behind it.

use chrono::Utc;

use crate::db::Database;

/// Spawns the daily snapshot loop. Fire-and-forget, same pattern as
/// `sessions::spawn_watchers`: a failure here should never take the server
/// down, it just means the next day's point is missing from the chart.
pub fn spawn_snapshot_job(db: Database) {
    tokio::spawn(run(db));
}

async fn run(db: Database) {
    // Write today's snapshot immediately on startup (covers the "server
    // restarted partway through the day" and "first deploy" cases), then
    // settle into a once-a-day cadence aligned to UTC midnight so the
    // history reads as clean calendar days.
    take_snapshot(&db).await;

    loop {
        let sleep_for = duration_until_next_utc_midnight();
        tokio::time::sleep(sleep_for).await;
        take_snapshot(&db).await;
    }
}

fn duration_until_next_utc_midnight() -> std::time::Duration {
    let now = Utc::now();
    let tomorrow_midnight = (now + chrono::Duration::days(1))
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();
    let secs = (tomorrow_midnight - now).num_seconds().max(1) as u64;
    std::time::Duration::from_secs(secs)
}

async fn take_snapshot(db: &Database) {
    let today = Utc::now().date_naive();

    let total: Result<i64, sqlx::Error> =
        sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await;

    let total = match total {
        Ok(n) => n,
        Err(e) => {
            eprintln!("⚠️  Couldn't count users for today's stats snapshot: {e}");
            return;
        }
    };

    let result = sqlx::query(
        r#"
        INSERT INTO user_count_snapshots (snapshot_date, total_users)
        VALUES ($1, $2)
        ON CONFLICT (snapshot_date)
        DO UPDATE SET total_users = EXCLUDED.total_users
        "#,
    )
    .bind(today)
    .bind(total)
    .execute(&db.pool)
    .await;

    if let Err(e) = result {
        eprintln!("⚠️  Couldn't write today's stats snapshot: {e}");
    }
}
