use sqlx::PgPool;
use uuid::Uuid;

use crate::{models::User, repositories, utils::AppResult};

pub async fn create_user(pool: &PgPool, user: &User) -> AppResult<User> {
    repositories::create_user(pool, user).await
}

pub async fn get_user_by_id(pool: &PgPool, id: Uuid) -> AppResult<Option<User>> {
    repositories::get_user_by_id(pool, id).await
}

pub async fn get_user_by_email(pool: &PgPool, email: &str) -> AppResult<Option<User>> {
    repositories::get_user_by_email(pool, email).await
}

pub async fn get_user_by_username(pool: &PgPool, username: &str) -> AppResult<Option<User>> {
    repositories::get_user_by_username(pool, username).await
}

pub async fn get_user_by_username_or_email(
    pool: &PgPool,
    username: &str,
    email: &str,
) -> AppResult<Option<User>> {
    repositories::get_user_by_username_or_email(pool, username, email).await
}

pub async fn get_all_users(pool: &PgPool, limit: i64, offset: i64) -> AppResult<Vec<User>> {
    repositories::get_all_users(pool, limit, offset).await
}

pub async fn update_user(pool: &PgPool, user: &User) -> AppResult<User> {
    repositories::update_user(pool, user).await
}

pub async fn delete_user(pool: &PgPool, id: Uuid) -> AppResult<()> {
    repositories::delete_user(pool, id).await
}

pub async fn get_user_by_github_id(pool: &PgPool, github_id: i64) -> AppResult<Option<User>> {
    repositories::get_user_by_github_id(pool, github_id).await
}
