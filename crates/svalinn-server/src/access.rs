//! Shared permission checks and upload helpers used by the route handlers.

use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;

/// Returns the user's role in the server, or `Forbidden` if they are not a
/// member. A site owner's role is always "owner".
pub async fn require_member(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<String, AppError> {
    let role: Option<Option<String>> = sqlx::query_scalar(
        r#"
        SELECT CASE WHEN u.site_role = 'owner' THEN 'owner' ELSE sm.role END
        FROM server_members sm JOIN users u ON u.id = sm.user_id
        WHERE sm.server_id = $1 AND sm.user_id = $2
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match role {
        Some(role) => Ok(role.unwrap_or_else(|| "member".to_string())),
        None => Err(AppError::Forbidden("You are not a member of this server".into())),
    }
}

/// Like `require_member`, but the user must also be an owner or admin.
pub async fn require_admin(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(), AppError> {
    let role = require_member(db, server_id, user_id).await?;
    if is_admin(&role) {
        Ok(())
    } else {
        Err(AppError::Forbidden("Only server admins can do this".into()))
    }
}

pub fn is_admin(role: &str) -> bool {
    matches!(role, "owner" | "admin")
}

/// Owners, admins and moderators can pin, lock and delete others' messages.
pub fn is_moderator(role: &str) -> bool {
    matches!(role, "owner" | "admin" | "moderator")
}

/// Rank of a site owner: above everyone, including each server's owner.
pub const SITE_OWNER_RANK: u8 = 5;

/// Rank used to decide who can kick or ban whom:
/// site owner > owner > admin > moderator > member.
/// You can only act on members ranked below you.
pub fn role_rank(role: &str, is_owner: bool) -> u8 {
    if is_owner {
        return 4;
    }
    match role {
        "owner" => 4,
        "admin" => 3,
        "moderator" => 2,
        _ => 1,
    }
}

/// The user's rank in the server, or `None` if they aren't a member.
pub async fn member_rank(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<Option<u8>, AppError> {
    let row: Option<(Option<String>, bool, bool)> = sqlx::query_as(
        r#"
        SELECT sm.role, s.owner_id = sm.user_id, COALESCE(u.site_role = 'owner', false)
        FROM server_members sm
        JOIN servers s ON s.id = sm.server_id
        JOIN users u ON u.id = sm.user_id
        WHERE sm.server_id = $1 AND sm.user_id = $2
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.map(|(role, is_owner, site_owner)| {
        if site_owner {
            SITE_OWNER_RANK
        } else {
            role_rank(role.as_deref().unwrap_or("member"), is_owner)
        }
    }))
}

/// Returns the server a channel belongs to, or `NotFound`.
pub async fn channel_server_id(db: &Database, channel_id: Uuid) -> Result<Uuid, AppError> {
    let server_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT server_id FROM channels WHERE id = $1")
            .bind(channel_id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    server_id
        .flatten()
        .ok_or_else(|| AppError::NotFound("Channel not found".into()))
}

/// Largest message attachment accepted, in bytes.
pub const MAX_ATTACHMENT_BYTES: usize = 100 * 1024 * 1024;
/// Largest custom emoji image accepted, in bytes.
pub const MAX_EMOJI_BYTES: usize = 2 * 1024 * 1024;
/// Non-pinned attachment bytes a single server may have stored across all
/// its channels at once -- see `routes::messages::check_attachment_quota`.
/// Independent of `MAX_ATTACHMENT_BYTES`: a server can still accept any
/// number of max-size attachments one at a time, this just stops the
/// *total* from growing without bound on local disk. A pinned message's
/// attachment doesn't count against it, same carve-out as the per-server
/// message cap (`retention::MESSAGE_CAP_PER_SERVER`).
pub const MAX_SERVER_ATTACHMENT_STORAGE_BYTES: i64 = 5 * 1024 * 1024 * 1024;
/// Request body limit for an upload of `max_file` bytes: the file plus room
/// for the other form fields and multipart framing.
pub const fn upload_body_limit(max_file: usize) -> usize {
    max_file + 1024 * 1024
}

/// Turns a multipart error into a clear message, especially for oversized files.
pub fn multipart_error(e: axum::extract::multipart::MultipartError, max_file: usize) -> AppError {
    if e.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge(format!(
            "File is too large. The limit is {} MB.",
            max_file / (1024 * 1024)
        ))
    } else {
        AppError::BadRequest(e.body_text())
    }
}

/// Extension to use for a stored upload. Only ASCII letters and digits are
/// kept, so a crafted filename like `x./../../evil` can't escape `uploads/`.
pub fn safe_extension(filename: &str, default: &str) -> String {
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if !ext.is_empty() && ext.len() <= 10 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        ext.to_ascii_lowercase()
    } else {
        default.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::safe_extension;

    #[test]
    fn keeps_normal_extensions() {
        assert_eq!(safe_extension("photo.PNG", "bin"), "png");
        assert_eq!(safe_extension("archive.tar.gz", "bin"), "gz");
    }

    #[test]
    fn rejects_path_tricks_and_missing_extensions() {
        assert_eq!(safe_extension("x./../../evil", "bin"), "bin");
        assert_eq!(safe_extension("a.p/hp", "bin"), "bin");
        assert_eq!(safe_extension("noext", "bin"), "bin");
        assert_eq!(safe_extension("", "png"), "png");
    }
}
