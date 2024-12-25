use anyhow::Ok;
use auth::{
    bootstrap::create_router,
    utils::{AppConfig, AppResult},
};
use axum::Router;
use sqlx::PgPool;

pub fn ctx(db_pool: PgPool) -> AppResult<Router> {
    dotenv::dotenv().ok();
    let config = AppConfig::new()?;

    Ok(create_router(db_pool, config))
}
