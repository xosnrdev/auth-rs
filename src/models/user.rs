use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::prelude::FromRow;
use uuid::Uuid;

//----------------------------------------------------------------------
// Types
//----------------------------------------------------------------------

/// Represents a user in the system.
///
/// This struct is designed to store and serialize user data for database interaction and API responses.
///
/// ## Fields
///
/// - `id` - A universally unique identifier (UUID) for the user.
/// - `github_id` - Optional GitHub ID of the user.
/// - `username` - The username of the user.
/// - `email` - The user's email address.
/// - `password_hash` - The hashed password (not serialized for security).
/// - `avatar_url` - Optional URL of the user's avatar image.
/// - `is_admin` - Boolean flag indicating if the user has admin privileges.
/// - `created_at` - Timestamp of user creation.
/// - `updated_at` - Timestamp of the last update.
#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_id: Option<i64>,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Creates a new `User` instance with default values for `id` and timestamps.
    ///
    /// ## Parameters
    /// - `github_id` - An optional GitHub ID of the user.
    /// - `email` - The user's email address.
    /// - `password_hash` - A hashed password for the user.
    /// - `username` - The username of the user.
    /// - `avatar_url` - Optional URL for the user's avatar image.
    ///
    /// ## Returns
    /// A new instance of `User`.
    pub fn new(
        github_id: Option<i64>,
        email: impl Into<String>,
        password_hash: impl Into<String>,
        username: impl Into<String>,
        avatar_url: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            github_id,
            username: username.into(),
            email: email.into(),
            password_hash: password_hash.into(),
            avatar_url,
            is_admin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

//----------------------------------------------------------------------
// Implementations
//----------------------------------------------------------------------

impl fmt::Display for User {
    /// Provides a human-readable representation of the `User` instance.
    ///
    /// ## Example Output
    /// ```console
    /// User: {
    ///   id: "550e8400-e29b-41d4-a716-446655440000",
    ///   github_id: Some(12345),
    ///   username: "john_doe",
    ///   email: "john@example.com",
    ///   avatar_url: Some("http://example.com/avatar.png"),
    ///   created_at: "2024-01-01T12:00:00Z",
    ///   updated_at: "2024-01-02T12:00:00Z"
    /// }
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User: {{ id: {}, github_id: {:?}, username: {}, email: {}, avatar_url: {:?}, created_at: {}, updated_at: {} }}",
            self.id,
            self.github_id,
            self.username,
            self.email,
            self.avatar_url,
            self.created_at,
            self.updated_at
        )
    }
}
