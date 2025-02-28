use serde::Serialize;

use crate::utils::{AppError, SuccessResponse};

#[derive(Serialize)]
pub struct ServiceInfo {
    name: String,
    version: String,
    description: String,
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn health_check() -> Result<SuccessResponse<ServiceInfo>, AppError> {
    let body = ServiceInfo {
        name: "auth-rs".to_string(),
        version: VERSION.to_string(),
        description: "A lightweight and modular authentication service proof of concept (PoC) written in Rust".to_string(),
    };
    Ok(SuccessResponse::ok(body))
}
