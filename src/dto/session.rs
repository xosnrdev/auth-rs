use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::Session;

#[derive(Debug, Deserialize)]
pub struct AccessTokenReqDto {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessTokenResDto {
    pub access_token: String,
    pub access_token_expires_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResDto {
    pub id: Uuid,
    pub user_id: Uuid,
    pub is_revoked: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<Session> for SessionResDto {
    fn from(session: Session) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id,
            is_revoked: session.is_revoked,
            expires_at: session.expires_at,
            created_at: session.created_at,
        }
    }
}
