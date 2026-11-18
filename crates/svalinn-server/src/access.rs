//! Shared permission checks and upload helpers used by the route handlers.

use uuid::Uuid;

use crate::db::Database;
use crate::errors::AppError;

/// Returns the user's role in the server, or `Forbidden` if they are not a member.
pub async fn require_member(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<String, AppError> {
    let role: Option<Option<String>> = sqlx::query_scalar(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
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
