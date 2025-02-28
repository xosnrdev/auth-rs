use anyhow::Context;
use config::{Config, Environment};
use getset::{Getters, Setters};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::{str::FromStr, sync::LazyLock};

use crate::utils::AppResult;

pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig::new().unwrap());

#[derive(Debug, Deserialize, Getters, Clone)]
pub struct AppConfig {
    #[getset(get = "pub with_prefix")]
    server: ServerConfig,
    #[getset(get = "pub with_prefix")]
    database: DatabaseConfig,
    pub environment: AppEnvironment,
    #[getset(get = "pub with_prefix")]
    jwt: JwtConfig,
}

impl AppConfig {
    pub fn new() -> AppResult<Self> {
        Config::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8000)?
            .set_default("server.timeout_in_secs", 10)?
            .set_default("server.origins", "localhost")?
            .set_default("server.rate_limit_per_secs", 100)?
            .set_default("server.rate_limit_burst", 10)?
            .set_default("database.host", "127.0.0.1")?
            .set_default("database.port", 5432)?
            .set_default("database.ssl_mode", "prefer")?
            .set_default("database.max_connections", 10)?
            .set_default("database.min_connections", 1)?
            .set_default("database.acquire_timeout_secs", 5)?
            .set_default("environment", "local")?
            .set_default("jwt.access_token_expiration_secs", 900)?
            .set_default("jwt.refresh_token_expiration_secs", 86400)?
            .set_default("redis.port", 6379)?
            .set_default("redis.host", "127.0.0.1")?
            .set_default("redis.db", 0)?
            .set_default("redis.tls_mode", false)?
            .set_default("rate_limit.requests_per_window", 100)?
            .set_default("rate_limit.window_size", 60)?
            .set_default("rate_limit.redis_uri", "redis://127.0.0.1")?
            .set_default("rate_limit.key_strategy", "token")?
            .add_source(Environment::with_prefix("APP").separator("__"))
            .build()?
            .try_deserialize()
            .context("Failed to deserialize configuration")
    }
}

#[derive(Debug, Deserialize, Getters, Clone)]
pub struct ServerConfig {
    #[getset(get = "pub with_prefix")]
    host: String,
    #[getset(get = "pub with_prefix")]
    port: u16,
    #[getset(get = "pub with_prefix")]
    timeout_in_secs: u64,
    #[getset(get = "pub with_prefix")]
    origins: String,
    #[getset(get = "pub with_prefix")]
    rate_limit_per_secs: u64,
    #[getset(get = "pub with_prefix")]
    rate_limit_burst: u64,
    #[getset(get = "pub with_prefix")]
    cookie_secret: String,
}

#[derive(Debug, Deserialize, Getters, Setters, Clone)]
pub struct DatabaseConfig {
    #[getset(get = "pub with_prefix")]
    #[serde(default)]
    username: String,
    #[getset(get = "pub with_prefix")]
    #[serde(default)]
    password: String,
    #[getset(get = "pub with_prefix")]
    #[serde(default)]
    port: u16,
    #[getset(get = "pub with_prefix")]
    #[serde(default)]
    host: String,
    #[getset(get = "pub")]
    #[serde(default)]
    name: String,
    #[getset(get = "pub with_prefix")]
    ssl_mode: PgSslModeExt,
    #[getset(get = "pub with_prefix")]
    max_connections: u32,
    #[getset(get = "pub with_prefix")]
    min_connections: u32,
    #[getset(get = "pub with_prefix")]
    acquire_timeout_secs: u64,
}

impl DatabaseConfig {
    pub fn to_pg_connect_options(&self) -> PgConnectOptions {
        PgConnectOptions::new()
            .username(&self.username)
            .password(&self.password)
            .port(self.port)
            .host(&self.host)
            .database(&self.name)
            .ssl_mode(self.ssl_mode.0)
    }
}

#[derive(Debug, Clone)]
pub struct PgSslModeExt(pub PgSslMode);

impl<'de> serde::Deserialize<'de> for PgSslModeExt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PgSslMode::from_str(&s)
            .map(PgSslModeExt)
            .map_err(serde::de::Error::custom)
    }
}

impl From<&str> for PgSslModeExt {
    fn from(s: &str) -> Self {
        PgSslModeExt(PgSslMode::from_str(s).unwrap_or_default())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum AppEnvironment {
    Local,
    Production,
}

#[derive(Debug, Deserialize, Getters, Clone)]
pub struct JwtConfig {
    #[getset(get = "pub with_prefix")]
    #[serde(default)]
    secret: String,
    #[getset(get = "pub with_prefix")]
    access_token_expiration_secs: i64,
    #[getset(get = "pub with_prefix")]
    refresh_token_expiration_secs: i64,
}
