//! Server-defined roles, member role assignment, and per-channel
//! permission overwrites. See `permissions.rs` for the bitflags and the
//! resolution algorithm this all feeds.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::access::{channel_server_id, require_member};
use crate::db::Database;
use crate::errors::AppError;
use crate::extractors::auth::CurrentUser;
use crate::models::message::BroadcastMessage;
use crate::permissions::{
    bits_from_names, is_unconditional_owner, resolve_channel, resolve_server, Bits, Permission, Permissions,
};

#[derive(Serialize, FromRow)]
pub struct Role {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub color: Option<String>,
    #[sqlx(rename = "permissions")]
    pub permission_bits: Bits,
    pub position: i32,
    pub is_default: bool,
}

impl Role {
    fn permission_names(&self) -> Vec<&'static str> {
        Permissions(self.permission_bits).names()
    }
}

#[derive(Serialize)]
pub struct RoleResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub color: Option<String>,
    pub permissions: Vec<&'static str>,
    pub position: i32,
    pub is_default: bool,
}

impl From<Role> for RoleResponse {
    fn from(r: Role) -> Self {
        RoleResponse {
            permissions: r.permission_names(),
            id: r.id,
            server_id: r.server_id,
            name: r.name,
            color: r.color,
            position: r.position,
            is_default: r.is_default,
        }
    }
}

/// The highest `position` among roles `user_id` holds in `server_id`, or
/// `-1` if they hold no custom (non-default) roles at all. Used to keep a
/// member with `MANAGE_ROLES` from creating, editing, deleting or
/// assigning a role ranked at or above their own highest role -- the
/// server owner and site owner are checked separately and always bypass
/// this (see each handler).
async fn actor_max_role_position(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<i32, AppError> {
    let max: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT MAX(r.position) FROM roles r
        JOIN member_roles mr ON mr.role_id = r.id
        WHERE mr.server_id = $1 AND mr.user_id = $2
        "#,
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(max.unwrap_or(-1))
}

/// The owner bypass plus the actor's resolved server permissions,
/// fetched together once per request. Every handler below needs both
/// "do they hold this permission" and "what exactly can they grant" from
/// the same resolution -- fetching it twice (or re-deriving `is_owner`
/// separately) was the duplication that used to make this file easy to
/// get subtly wrong (and, before a review caught it, actually did: see
/// the overwrite endpoints' history).
async fn actor_context(db: &Database, server_id: Uuid, user_id: Uuid) -> Result<(bool, Permissions), AppError> {
    if is_unconditional_owner(db, server_id, user_id).await? {
        return Ok((true, Permissions::ALL));
    }
    Ok((false, resolve_server(db, server_id, user_id).await?))
}

/// Rejects `bits` the actor doesn't themselves hold (owners always pass)
/// -- the "can't grant a permission you don't have yourself" rule shared
/// by role creation/editing and channel overwrites.
fn reject_ungranted_bits(is_owner: bool, actor_perms: Permissions, bits: Bits) -> Result<(), AppError> {
    if is_owner || bits & !actor_perms.0 == 0 {
        return Ok(());
    }
    Err(AppError::BadRequest("You can't grant a permission you don't have yourself".into()))
}

/// `position` must rank below the actor's own highest role, unless
/// they're the unconditional owner -- the hierarchy guard that keeps
/// `MANAGE_ROLES` (directly, or via `MANAGE_CHANNELS` on channel
/// overwrites) from reaching or exceeding the actor's own rank, shared
/// by role management and channel overwrites.
async fn require_below_actor_rank(
    db: &Database,
    server_id: Uuid,
    user_id: Uuid,
    is_owner: bool,
    position: i32,
    error: &str,
) -> Result<(), AppError> {
    if is_owner {
        return Ok(());
    }
    let actor_max = actor_max_role_position(db, server_id, user_id).await?;
    if position >= actor_max {
        return Err(AppError::Forbidden(error.into()));
    }
    Ok(())
}

/// Requires `MANAGE_ROLES` and that `role_position` ranks below the
/// actor's own highest role -- `is_owner`/`actor_perms` are the caller's
/// already-fetched `actor_context`, so this makes no DB call of its own
/// beyond the rank check.
async fn require_role_management(
    db: &Database,
    server_id: Uuid,
    user_id: Uuid,
    is_owner: bool,
    actor_perms: Permissions,
    role_position: i32,
) -> Result<(), AppError> {
    if is_owner {
        return Ok(());
    }
    if !actor_perms.has(Permission::MANAGE_ROLES) {
        return Err(AppError::Forbidden("You don't have the manage_roles permission in this server".into()));
    }
    require_below_actor_rank(db, server_id, user_id, is_owner, role_position, "You can only manage roles ranked below your own").await
}

/// GET /api/v1/servers/:server_id/roles
pub async fn list_roles(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<RoleResponse>>, AppError> {
    require_member(&db, server_id, user_id).await?;
    let roles: Vec<Role> = sqlx::query_as(
        "SELECT id, server_id, name, color, permissions, position, is_default FROM roles WHERE server_id = $1 ORDER BY position DESC",
    )
    .bind(server_id)
    .fetch_all(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(Json(roles.into_iter().map(RoleResponse::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub color: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// POST /api/v1/servers/:server_id/roles
///
/// A role can only be created with permissions the creator themselves
/// has (in the server as a whole) -- otherwise `MANAGE_ROLES` alone would
/// let anyone mint themselves an `administrator` role.
pub async fn create_role(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, AppError> {
    let (is_owner, actor_perms) = actor_context(&db, server_id, user_id).await?;
    if !is_owner && !actor_perms.has(Permission::MANAGE_ROLES) {
        return Err(AppError::Forbidden("You don't have the manage_roles permission in this server".into()));
    }

    let name = payload.name.trim();
    if name.is_empty() || name.len() > 50 {
        return Err(AppError::BadRequest("Role name must be 1-50 characters".into()));
    }
    let bits = bits_from_names(&payload.permissions)?;
    reject_ungranted_bits(is_owner, actor_perms, bits)?;

    let next_position: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(position), -1) + 1 FROM roles WHERE server_id = $1")
            .bind(server_id)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    let role: Role = sqlx::query_as(
        r#"
        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        VALUES ($1, $2, $3, $4, $5, false)
        RETURNING id, server_id, name, color, permissions, position, is_default
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(&payload.color)
    .bind(bits)
    .bind(next_position)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let response = RoleResponse::from(role);
    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "role_created",
        serde_json::to_value(&response).unwrap_or_default(),
        server_id,
    ));
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub color: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub position: Option<i32>,
}

/// PATCH /api/v1/servers/:server_id/roles/:role_id
pub async fn update_role(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((server_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, AppError> {
    let existing: Option<Role> = sqlx::query_as(
        "SELECT id, server_id, name, color, permissions, position, is_default FROM roles WHERE id = $1 AND server_id = $2",
    )
    .bind(role_id)
    .bind(server_id)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let Some(existing) = existing else {
        return Err(AppError::NotFound("Role not found".into()));
    };

    let (is_owner, actor_perms) = actor_context(&db, server_id, user_id).await?;
    require_role_management(&db, server_id, user_id, is_owner, actor_perms, existing.position).await?;

    let name = match &payload.name {
        Some(n) => {
            let n = n.trim();
            if n.is_empty() || n.len() > 50 {
                return Err(AppError::BadRequest("Role name must be 1-50 characters".into()));
            }
            n.to_string()
        }
        None => existing.name.clone(),
    };
    let color = if payload.color.is_some() { payload.color.clone() } else { existing.color.clone() };
    let bits = match &payload.permissions {
        Some(names) => {
            let bits = bits_from_names(names)?;
            reject_ungranted_bits(is_owner, actor_perms, bits)?;
            bits
        }
        None => existing.permission_bits,
    };
    let position = match payload.position {
        // The default role's position is meaningless (it's implicit for
        // everyone regardless of ordering) and kept fixed at 0.
        Some(_) if existing.is_default => existing.position,
        Some(p) => {
            require_below_actor_rank(&db, server_id, user_id, is_owner, p, "You can't move a role to or above your own rank").await?;
            p
        }
        None => existing.position,
    };

    let role: Role = sqlx::query_as(
        r#"
        UPDATE roles SET name = $1, color = $2, permissions = $3, position = $4
        WHERE id = $5 AND server_id = $6
        RETURNING id, server_id, name, color, permissions, position, is_default
        "#,
    )
    .bind(&name)
    .bind(&color)
    .bind(bits)
    .bind(position)
    .bind(role_id)
    .bind(server_id)
    .fetch_one(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let response = RoleResponse::from(role);
    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "role_updated",
        serde_json::to_value(&response).unwrap_or_default(),
        server_id,
    ));
    Ok(Json(response))
}

/// DELETE /api/v1/servers/:server_id/roles/:role_id
pub async fn delete_role(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((server_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let existing: Option<(i32, bool)> =
        sqlx::query_as("SELECT position, is_default FROM roles WHERE id = $1 AND server_id = $2")
            .bind(role_id)
            .bind(server_id)
            .fetch_optional(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let Some((position, is_default)) = existing else {
        return Err(AppError::NotFound("Role not found".into()));
    };
    if is_default {
        return Err(AppError::BadRequest("The default role can't be deleted".into()));
    }
    let (is_owner, actor_perms) = actor_context(&db, server_id, user_id).await?;
    require_role_management(&db, server_id, user_id, is_owner, actor_perms, position).await?;

    sqlx::query("DELETE FROM roles WHERE id = $1 AND server_id = $2")
        .bind(role_id)
        .bind(server_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "role_deleted",
        serde_json::json!({ "server_id": server_id, "role_id": role_id }),
        server_id,
    ));
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn role_position(db: &Database, server_id: Uuid, role_id: Uuid) -> Result<i32, AppError> {
    sqlx::query_scalar("SELECT position FROM roles WHERE id = $1 AND server_id = $2")
        .bind(role_id)
        .bind(server_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Role not found".into()))
}

/// PUT /api/v1/servers/:server_id/members/:user_id/roles/:role_id
pub async fn assign_role(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target, role_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let position = role_position(&db, server_id, role_id).await?;
    let (is_owner, actor_perms) = actor_context(&db, server_id, actor).await?;
    require_role_management(&db, server_id, actor, is_owner, actor_perms, position).await?;
    if require_member(&db, server_id, target).await.is_err() {
        return Err(AppError::NotFound("That user isn't a member of this server".into()));
    }

    sqlx::query("INSERT INTO member_roles (server_id, user_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(server_id)
        .bind(target)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "member_role_assigned",
        serde_json::json!({ "server_id": server_id, "user_id": target, "role_id": role_id }),
        server_id,
    ));
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/servers/:server_id/members/:user_id/roles/:role_id
pub async fn unassign_role(
    State(db): State<Database>,
    CurrentUser(actor): CurrentUser,
    Path((server_id, target, role_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let position = role_position(&db, server_id, role_id).await?;
    let (is_owner, actor_perms) = actor_context(&db, server_id, actor).await?;
    require_role_management(&db, server_id, actor, is_owner, actor_perms, position).await?;

    sqlx::query("DELETE FROM member_roles WHERE server_id = $1 AND user_id = $2 AND role_id = $3")
        .bind(server_id)
        .bind(target)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "member_role_unassigned",
        serde_json::json!({ "server_id": server_id, "user_id": target, "role_id": role_id }),
        server_id,
    ));
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct MyPermissionsResponse {
    pub permissions: Vec<&'static str>,
}

/// GET /api/v1/servers/:server_id/permissions/me
pub async fn my_server_permissions(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<MyPermissionsResponse>, AppError> {
    let perms = resolve_server(&db, server_id, user_id).await?;
    Ok(Json(MyPermissionsResponse { permissions: perms.names() }))
}

/// GET /api/v1/channels/:channel_id/permissions/me
pub async fn my_channel_permissions(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<MyPermissionsResponse>, AppError> {
    let perms = resolve_channel(&db, channel_id, user_id).await?;
    Ok(Json(MyPermissionsResponse { permissions: perms.names() }))
}

#[derive(Serialize, FromRow)]
pub struct RoleOverwrite {
    pub role_id: Uuid,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Serialize, FromRow)]
pub struct MemberOverwrite {
    pub user_id: Uuid,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Serialize)]
pub struct ChannelOverwritesResponse {
    pub roles: Vec<RoleOverwrite>,
    pub members: Vec<MemberOverwrite>,
}

fn names(bits: Bits) -> Vec<String> {
    Permissions(bits).names().into_iter().map(String::from).collect()
}

/// GET /api/v1/channels/:channel_id/overwrites
pub async fn list_channel_overwrites(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelOverwritesResponse>, AppError> {
    let server_id = channel_server_id(&db, channel_id).await?;
    let (is_owner, actor_perms) = actor_context(&db, server_id, user_id).await?;
    if !is_owner && !actor_perms.has(Permission::MANAGE_CHANNELS) && !actor_perms.has(Permission::MANAGE_ROLES) {
        return Err(AppError::Forbidden("You don't have permission to view this channel's overwrites".into()));
    }

    let role_rows: Vec<(Uuid, Bits, Bits)> =
        sqlx::query_as("SELECT role_id, allow, deny FROM channel_role_overwrites WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let member_rows: Vec<(Uuid, Bits, Bits)> =
        sqlx::query_as("SELECT user_id, allow, deny FROM channel_member_overwrites WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_all(&db.pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(ChannelOverwritesResponse {
        roles: role_rows.into_iter().map(|(role_id, allow, deny)| RoleOverwrite { role_id, allow: names(allow), deny: names(deny) }).collect(),
        members: member_rows.into_iter().map(|(user_id, allow, deny)| MemberOverwrite { user_id, allow: names(allow), deny: names(deny) }).collect(),
    }))
}

#[derive(Deserialize)]
pub struct SetOverwriteRequest {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

async fn require_channel_overwrite_management(
    db: &Database,
    channel_id: Uuid,
    user_id: Uuid,
) -> Result<(Uuid, bool, Permissions), AppError> {
    let server_id = channel_server_id(db, channel_id).await?;
    let (is_owner, actor_perms) = actor_context(db, server_id, user_id).await?;
    if !is_owner && !actor_perms.has(Permission::MANAGE_CHANNELS) && !actor_perms.has(Permission::MANAGE_ROLES) {
        return Err(AppError::Forbidden("You don't have permission to manage this channel's overwrites".into()));
    }
    Ok((server_id, is_owner, actor_perms))
}

fn validate_overwrite(allow: &[String], deny: &[String]) -> Result<(Bits, Bits), AppError> {
    let allow_bits = bits_from_names(allow)?;
    let deny_bits = bits_from_names(deny)?;
    Ok((allow_bits, deny_bits))
}

const OVERWRITE_RANK_ERROR: &str = "You can only set overwrites for a role or member ranked below your own";

/// Tells every client on the server that a channel's permission overwrites
/// changed, so a client whose access to that channel was just revoked (or
/// granted) can refresh rather than sitting on a stale view until its next
/// unrelated re-fetch. Broadcast broadly (like `role_updated` and
/// `member_role_assigned`/`unassigned` already are) rather than only to
/// whoever's affected -- this is an infrequent admin action, and working
/// out exactly who gained or lost access would mean re-deriving
/// permissions for every member for every edit; each client already knows
/// to just re-check its own access when it sees this.
fn broadcast_overwrite_changed(db: &Database, server_id: Uuid, channel_id: Uuid) {
    let _ = db.message_tx.send(BroadcastMessage::to_server(
        "channel_overwrite_changed",
        serde_json::json!({ "server_id": server_id, "channel_id": channel_id }),
        server_id,
    ));
}

/// PUT /api/v1/channels/:channel_id/overwrites/role/:role_id
pub async fn set_role_overwrite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((channel_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<SetOverwriteRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let (server_id, is_owner, actor_perms) = require_channel_overwrite_management(&db, channel_id, user_id).await?;
    let target_position = role_position(&db, server_id, role_id).await?; // 404s if the role isn't on this server
    require_below_actor_rank(&db, server_id, user_id, is_owner, target_position, OVERWRITE_RANK_ERROR).await?;
    let (allow, deny) = validate_overwrite(&payload.allow, &payload.deny)?;
    reject_ungranted_bits(is_owner, actor_perms, allow)?;

    sqlx::query(
        r#"
        INSERT INTO channel_role_overwrites (channel_id, role_id, allow, deny) VALUES ($1, $2, $3, $4)
        ON CONFLICT (channel_id, role_id) DO UPDATE SET allow = $3, deny = $4
        "#,
    )
    .bind(channel_id)
    .bind(role_id)
    .bind(allow)
    .bind(deny)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    broadcast_overwrite_changed(&db, server_id, channel_id);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/channels/:channel_id/overwrites/role/:role_id
pub async fn delete_role_overwrite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((channel_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let (server_id, is_owner, _) = require_channel_overwrite_management(&db, channel_id, user_id).await?;
    let target_position = role_position(&db, server_id, role_id).await?;
    require_below_actor_rank(&db, server_id, user_id, is_owner, target_position, OVERWRITE_RANK_ERROR).await?;
    sqlx::query("DELETE FROM channel_role_overwrites WHERE channel_id = $1 AND role_id = $2")
        .bind(channel_id)
        .bind(role_id)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    broadcast_overwrite_changed(&db, server_id, channel_id);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// PUT /api/v1/channels/:channel_id/overwrites/member/:user_id
pub async fn set_member_overwrite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((channel_id, target)): Path<(Uuid, Uuid)>,
    Json(payload): Json<SetOverwriteRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let (server_id, is_owner, actor_perms) = require_channel_overwrite_management(&db, channel_id, user_id).await?;
    if require_member(&db, server_id, target).await.is_err() {
        return Err(AppError::NotFound("That user isn't a member of this server".into()));
    }
    // A member has no "position" of their own -- use their highest
    // assigned role as the hierarchy stand-in, same as `actor_max_role_position`
    // does for the actor. A target with no custom roles ranks at -1,
    // i.e. below everyone, same as `require_role_management`'s baseline.
    let target_position = actor_max_role_position(&db, server_id, target).await?;
    require_below_actor_rank(&db, server_id, user_id, is_owner, target_position, OVERWRITE_RANK_ERROR).await?;
    let (allow, deny) = validate_overwrite(&payload.allow, &payload.deny)?;
    reject_ungranted_bits(is_owner, actor_perms, allow)?;

    sqlx::query(
        r#"
        INSERT INTO channel_member_overwrites (channel_id, user_id, allow, deny) VALUES ($1, $2, $3, $4)
        ON CONFLICT (channel_id, user_id) DO UPDATE SET allow = $3, deny = $4
        "#,
    )
    .bind(channel_id)
    .bind(target)
    .bind(allow)
    .bind(deny)
    .execute(&db.pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    broadcast_overwrite_changed(&db, server_id, channel_id);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/channels/:channel_id/overwrites/member/:user_id
pub async fn delete_member_overwrite(
    State(db): State<Database>,
    CurrentUser(user_id): CurrentUser,
    Path((channel_id, target)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, AppError> {
    let (server_id, is_owner, _) = require_channel_overwrite_management(&db, channel_id, user_id).await?;
    let target_position = actor_max_role_position(&db, server_id, target).await?;
    require_below_actor_rank(&db, server_id, user_id, is_owner, target_position, OVERWRITE_RANK_ERROR).await?;
    sqlx::query("DELETE FROM channel_member_overwrites WHERE channel_id = $1 AND user_id = $2")
        .bind(channel_id)
        .bind(target)
        .execute(&db.pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    broadcast_overwrite_changed(&db, server_id, channel_id);
    Ok(axum::http::StatusCode::NO_CONTENT)
}
