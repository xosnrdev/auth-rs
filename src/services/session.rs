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
