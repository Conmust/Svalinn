//! Public, read-only aggregate stats.
//!
//! These two endpoints exist so the community can be told "how many people
//! have signed up" without that requiring anything that tracks who those
//! people are. Every response here is a count or a list of (date, count)
//! pairs -- never a user id, a username, or anything else that identifies
//! an individual account.
//!
//! Both routes are intentionally public (no `CurrentUser`/`CurrentSession`
//! extractor) and send their own permissive CORS header so a plain static
//! web page -- not just the desktop app -- can poll them directly, without
//! needing its origin added to `CORS_ALLOWED_ORIGINS`.

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::db::Database;
use crate::errors::AppError;

/// Any origin may read these; it's a single public aggregate number, not
/// user data, so there's nothing a stricter policy would protect.
fn with_public_cors<T: IntoResponse>(body: T) -> impl IntoResponse {
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], body)
}

#[derive(Serialize)]
pub struct UserCountResponse {
    pub total_users: i64,
    pub as_of: chrono::DateTime<chrono::Utc>,
}

/// GET /api/v1/stats/user-count
///
/// The current total, computed fresh every call -- always accurate, never
/// stale by more than the time it takes to run `COUNT(*)`.
pub async fn get_user_count(State(db): State<Database>) -> Result<impl IntoResponse, AppError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(with_public_cors(Json(UserCountResponse {
        total_users: total,
        as_of: chrono::Utc::now(),
    })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    days: Option<i64>,
}

#[derive(Serialize)]
pub struct UserCountPoint {
    pub date: NaiveDate,
    pub total_users: i64,
}

#[derive(Serialize)]
pub struct UserCountHistoryResponse {
    pub points: Vec<UserCountPoint>,
}

const DEFAULT_HISTORY_DAYS: i64 = 30;
const MAX_HISTORY_DAYS: i64 = 365;

/// GET /api/v1/stats/user-count/history?days=30
///
/// Daily snapshots for a growth chart, most recent `days` calendar days
/// (default 30, capped at 365). The most recent point is always today's
/// *live* count rather than last night's snapshot, so the chart's latest
/// bar never looks stale right after a burst of signups.
pub async fn get_user_count_history(
    State(db): State<Database>,
    Query(q): Query<HistoryQuery>,
) -> Result<impl IntoResponse, AppError> {
    let days = q.days.unwrap_or(DEFAULT_HISTORY_DAYS).clamp(1, MAX_HISTORY_DAYS);

    let mut points: Vec<UserCountPoint> = sqlx::query_as(
        r#"
        SELECT snapshot_date AS date, total_users
        FROM user_count_snapshots
        WHERE snapshot_date >= (CURRENT_DATE - ($1::bigint - 1) * INTERVAL '1 day')
          AND snapshot_date < CURRENT_DATE
        ORDER BY snapshot_date ASC
        "#,
    )
    .bind(days)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .into_iter()
    .map(|(date, total_users): (NaiveDate, i64)| UserCountPoint { date, total_users })
    .collect();

    let today_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    points.push(UserCountPoint {
        date: chrono::Utc::now().date_naive(),
        total_users: today_total,
    });

    Ok(with_public_cors(Json(UserCountHistoryResponse { points })))
}
