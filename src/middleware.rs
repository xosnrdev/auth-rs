#![deny(missing_docs)]
//! This module provides middleware extractors for handling JWT authorization,
//! ensuring requests contain valid access or refresh tokens where needed.

use crate::{
    bootstrap::AppState,
    services::get_session_by_user_id,
    token::{Claims, TokenManager},
    utils::AppError,
};
use axum::{
    RequestPartsExt,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use axum_extra::{
    TypedHeader,
    extract::PrivateCookieJar,
    headers::{Authorization, authorization::Bearer},
};

/// Middleware extractor that validates the `Authorization: Bearer` header for access tokens.
///
/// If the token is invalid or missing, it returns an `AppError` with a `UNAUTHORIZED` status.
impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract and validate bearer token
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| AppError::new(StatusCode::UNAUTHORIZED, format!("{}", e)))?;

        // Configure the TokenManager
        let token_manager =
            TokenManager::new(state.get_config().get_jwt().get_secret().as_bytes(), None);

        // Validate the token format and signature
        let claims = token_manager
            .validate_access_token(bearer.token())
            .map_err(|e| AppError::new(StatusCode::UNAUTHORIZED, format!("{}", e)))?;

        // For admin users, we only check if their own session is valid
        // This allows them to manage other sessions even if those sessions are revoked
        if *claims.get_is_admin() {
            if let Some(session) =
                get_session_by_user_id(state.get_db_pool(), *claims.get_jti()).await?
            {
                if session.is_revoked || session.is_expired() {
                    return Err(AppError::new(
                        StatusCode::UNAUTHORIZED,
                        "Admin session has been revoked or expired",
                    ));
                }
                return Ok(claims);
            }
            return Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                "Invalid admin session",
            ));
        }

        // For non-admin users, check their session as before
        if let Some(session) =
            get_session_by_user_id(state.get_db_pool(), *claims.get_jti()).await?
        {
            if session.is_revoked || session.is_expired() {
                return Err(AppError::new(
                    StatusCode::UNAUTHORIZED,
                    "Session has been revoked or expired",
                ));
            }
            return Ok(claims);
        }

        Err(AppError::new(StatusCode::UNAUTHORIZED, "Invalid session"))
    }
}

/// A wrapper type to signal that the contained `Claims` come from a refresh token.
pub struct RefreshClaims(pub Claims);

/// Middleware extractor that validates the presence and validity of a refresh token stored in cookies.
///
/// If the refresh token is invalid, missing, or expired, returns an `AppError` with `UNAUTHORIZED`.
impl FromRequestParts<AppState> for RefreshClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = PrivateCookieJar::from_request_parts(parts, state.get_key())
            .await
            .map_err(|e| AppError::new(StatusCode::UNAUTHORIZED, format!("{}", e)))?;

        if let Some(token) = get_session_token(&jar) {
            let token_manager =
                TokenManager::new(state.get_config().get_jwt().get_secret().as_bytes(), None);

            token_manager
                .validate_refresh_token(&token)
                .map(RefreshClaims)
                .map_err(|e| AppError::new(StatusCode::UNAUTHORIZED, format!("{}", e)))
        } else {
            Err(AppError::new(
                StatusCode::UNAUTHORIZED,
                "Missing refresh token",
            ))
        }
    }
}

/// Extracts the `refresh_token` from the user's cookie jar.
///
/// Returns `Some(token)` if present, otherwise `None`.
fn get_session_token(jar: &PrivateCookieJar) -> Option<String> {
    jar.get("refresh_token")
        .map(|cookie| cookie.value().to_owned())
}

/// Checks if the user has admin privileges.
pub fn check_admin(claims: &Claims) -> Result<(), AppError> {
    if !claims.get_is_admin() {
        Err(AppError::new(
            StatusCode::FORBIDDEN,
            "Access denied: admin privileges required",
        ))
    } else {
        Ok(())
    }
}
