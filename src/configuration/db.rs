use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[derive(Deserialize)]
pub struct DbConfig {
    pub username: String,
    password: String,
    pub port: u16,
    pub host: String,
    pub database_name: String,
    pub ssl_mode: SslMode,
}

#[derive(Deserialize)]
pub enum SslMode {
    Require,
    Prefer,
    Disable,
}

impl DbConfig {
    pub fn new(
        username: String,
        password: String,
        port: u16,
        host: String,
        database_name: String,
        ssl_mode: SslMode,
    ) -> Self {
        Self {
            username,
            password,
            port,
            host,
            database_name,
            ssl_mode,
        }
    }

    pub fn to_pg_connect_options(&self) -> PgConnectOptions {
        PgConnectOptions::new()
            .username(&self.username)
            .password(&self.password)
            .port(self.port)
            .host(&self.host)
            .database(&self.database_name)
            .ssl_mode(match self.ssl_mode {
                SslMode::Require => PgSslMode::Require,
                SslMode::Prefer => PgSslMode::Prefer,
                SslMode::Disable => PgSslMode::Disable,
            })
    }
}
