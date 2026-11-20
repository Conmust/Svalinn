use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::access::{safe_extension, MAX_ATTACHMENT_BYTES};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;

#[derive(Serialize)]
pub struct UploadResponse {
    pub url: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
}

pub async fn upload_file(
    State(_db): State<Database>,
    CurrentUser(_user_id): CurrentUser,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    // Ensure uploads directory exists
    let uploads_dir = std::path::Path::new("uploads");
    if !uploads_dir.exists() {
        std::fs::create_dir_all(uploads_dir)
            .map_err(|e| AppError::Internal(format!("Failed to create uploads dir: {}", e)))?;
    }

    let field = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read field: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("No file provided".into()))?;

    let original_filename = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "file".to_string());

    let content_type = field
        .content_type()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let data = field
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read file data: {}", e)))?;

    if data.len() > MAX_ATTACHMENT_BYTES {
        return Err(AppError::BadRequest(format!(
            "File exceeds the {}MB size limit",
            MAX_ATTACHMENT_BYTES / (1024 * 1024)
        )));
    }

    // Generate a UUID filename with an allowlisted extension -- same
    // `safe_extension` used for channel/emoji uploads (messages.rs,
    // emojis.rs), rather than taking whatever's after the last `.` as-is.
    // `Path::extension()` alone can't be used for a path-traversal escape
    // (it can never contain a `/`, by construction -- it's drawn only from
    // within the last path component), so this wasn't itself exploitable,
    // but routing every upload path through the same allowlist keeps this
    // handler consistent with the rest of the codebase instead of being
    // the one upload path with a different, ad hoc rule.
    let extension = safe_extension(&original_filename, "bin");
    let stored_filename = format!("{}.{}", Uuid::new_v4(), extension);
    let file_path = uploads_dir.join(&stored_filename);

    tokio::fs::write(&file_path, &data)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to save file: {}", e)))?;

    let url = format!("/uploads/{}", stored_filename);

    Ok(Json(UploadResponse {
        url,
        filename: original_filename,
        size: data.len() as u64,
        mime_type: content_type,
    }))
}