use crate::{models::Session, utils::AppResult};
use anyhow::anyhow;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn create_session(pool: &PgPool, session: &Session) -> AppResult<Session> {
    sqlx::query_as!(
        Session,
        r#"
        INSERT INTO sessions (id, user_id, refresh_token, expires_at, is_revoked, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
        session.id,
        session.user_id,
        session.refresh_token,
        session.expires_at,
        session.is_revoked,
        session.created_at,
        session.updated_at
    )
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow!("Unable to create session ({})", e))
}

pub async fn get_session_by_user_id(pool: &PgPool, user_id: Uuid) -> AppResult<Option<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT * FROM sessions
        WHERE user_id = $1
        "#,
        user_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| anyhow!("Unable to get session by ID ({})", e))
}

pub async fn revoke_session(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query!(
        r#"
        UPDATE sessions
        SET is_revoked = true, updated_at = $1
        WHERE user_id = $2
        "#,
        Utc::now(),
        user_id,
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow!("Unable to revoke session ({})", e))?;
    Ok(())
}

pub async fn delete_session_by_user_id(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query!(
        r#"
        DELETE FROM sessions
        WHERE user_id = $1
        "#,
        user_id
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow!("Unable to delete session ({})", e))?;
    Ok(())
}

pub async fn get_session_by_id(pool: &PgPool, session_id: Uuid) -> AppResult<Option<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT * FROM sessions
        WHERE id = $1
        "#,
        session_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| anyhow!("Unable to get session by ID ({})", e))
}

pub async fn revoke_session_by_id(pool: &PgPool, session_id: Uuid) -> AppResult<()> {
    sqlx::query!(
        r#"
        UPDATE sessions
        SET is_revoked = true, updated_at = $1
        WHERE id = $2
        "#,
        Utc::now(),
        session_id,
    )
    .execute(pool)
    .await
    .map_err(|e| anyhow!("Unable to revoke session ({})", e))?;
    Ok(())
}

pub async fn list_active_sessions(pool: &PgPool) -> AppResult<Vec<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT * FROM sessions
        WHERE is_revoked = false AND expires_at > NOW()
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow!("Unable to list active sessions ({})", e))
}

pub async fn list_user_active_sessions(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<Session>> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT * FROM sessions
        WHERE user_id = $1 AND is_revoked = false AND expires_at > NOW()
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow!("Unable to list user active sessions ({})", e))
}
