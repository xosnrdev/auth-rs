use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::prelude::FromRow;
use uuid::Uuid;

//----------------------------------------------------------------------
// Types
//----------------------------------------------------------------------

/// Represents a user session in the system.
///
/// This struct is designed to handle session management, including token storage and expiration handling.
///
/// ## Fields
/// - `id` - A unique identifier for the session.
/// - `user_id` - The unique ID of the user associated with this session.
/// - `refresh_token` - A token used to refresh the session.
/// - `is_revoked` - Indicates whether the session has been revoked.
/// - `expires_at` - Timestamp when the session expires.
/// - `created_at` - Timestamp when the session was created.
/// - `updated_at` - Timestamp of the last update.
#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub refresh_token: String,
    pub is_revoked: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

//----------------------------------------------------------------------
// Implementations
//----------------------------------------------------------------------

impl Session {
    /// Creates a new `Session` instance with default values for `id`, timestamps, and revocation status.
    ///
    /// ## Parameters
    /// - `user_id` - The unique ID of the user associated with this session.
    /// - `refresh_token` - A token string used to refresh the session.
    /// - `duration` - A `chrono::Duration` indicating the session's lifespan.
    ///
    /// ## Returns
    /// A new `Session` instance.
    pub fn new(user_id: Uuid, refresh_token: impl Into<String>, duration: Duration) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            refresh_token: refresh_token.into(),
            is_revoked: false,
            expires_at: Utc::now() + duration,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Checks if the session has expired.
    ///
    /// ## Returns
    /// - `true` if the current timestamp is past the `expires_at` timestamp.
    /// - `false` otherwise.
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

impl fmt::Display for Session {
    /// Provides a human-readable representation of the `Session` instance.
    ///
    /// ## Example Output
    /// ```console
    /// Session: {
    ///   id: "550e8400-e29b-41d4-a716-446655440000",
    ///   user_id: "123e4567-e89b-12d3-a456-426614174000",
    ///   is_revoked: false,
    ///   expires_at: "2024-01-01T12:00:00Z",
    ///   created_at: "2024-01-01T11:00:00Z",
    ///   updated_at: "2024-01-01T11:00:00Z"
    /// }
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Session: {{ id: {}, user_id: {}, is_revoked: {}, expires_at: {}, created_at: {}, updated_at: {} }}",
            self.id,
            self.user_id,
            self.is_revoked,
            self.expires_at,
            self.created_at,
            self.updated_at
        )
    }
}
