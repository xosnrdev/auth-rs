use sqlx::PgPool;
use uuid::Uuid;

use crate::{models::Session, repositories, utils::AppResult};

pub async fn create_session(pool: &PgPool, session: &Session) -> AppResult<Session> {
    repositories::create_session(pool, session).await
}

pub async fn get_session_by_user_id(pool: &PgPool, user_id: Uuid) -> AppResult<Option<Session>> {
    repositories::get_session_by_user_id(pool, user_id).await
}

pub async fn revoke_session(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    repositories::revoke_session(pool, user_id).await
}

pub async fn delete_session_by_user_id(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    repositories::delete_session_by_user_id(pool, user_id).await
}

pub async fn get_session_by_id(pool: &PgPool, session_id: Uuid) -> AppResult<Option<Session>> {
    repositories::get_session_by_id(pool, session_id).await
}

pub async fn revoke_session_by_id(pool: &PgPool, session_id: Uuid) -> AppResult<()> {
    repositories::revoke_session_by_id(pool, session_id).await
}

pub async fn list_active_sessions(pool: &PgPool) -> AppResult<Vec<Session>> {
    repositories::list_active_sessions(pool).await
}

pub async fn list_user_active_sessions(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<Session>> {
    repositories::list_user_active_sessions(pool, user_id).await
}
