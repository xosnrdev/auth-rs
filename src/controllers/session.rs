use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::PrivateCookieJar;
use chrono::Duration;
use uuid::Uuid;

use crate::{
    bootstrap::AppState,
    dto::{AccessTokenReqDto, AccessTokenResDto, SessionResDto},
    middleware::check_admin,
    services::{
        delete_session_by_user_id, get_session_by_id, get_session_by_user_id, list_active_sessions,
        list_user_active_sessions, revoke_session, revoke_session_by_id,
    },
    token::{Claims, TokenManager},
    utils::{AppError, SuccessResponse},
};

use super::create_cookie_session;

pub async fn refresh_session_by_cookie(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<SuccessResponse<AccessTokenResDto>, AppError> {
    let token = jar
        .get("refresh_token")
        .or_else(|| jar.get("refreshToken"))
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "Missing refresh token"))?;

    let token_manager =
        TokenManager::new(state.get_config().get_jwt().get_secret().as_bytes(), None);

    let claims = token_manager.validate_refresh_token(&token)?;

    handle_stale_sessions(
        &state,
        *claims.get_jti(),
        *claims.get_is_admin(),
        claims.get_sub(),
        token_manager,
    )
    .await
}

pub async fn refresh_session_by_body(
    State(state): State<AppState>,
    Json(dto): Json<AccessTokenReqDto>,
) -> Result<SuccessResponse<AccessTokenResDto>, AppError> {
    let token_manager =
        TokenManager::new(state.get_config().get_jwt().get_secret().as_bytes(), None);

    let token = token_manager.validate_refresh_token(&dto.refresh_token)?;

    handle_stale_sessions(
        &state,
        *token.get_jti(),
        *token.get_is_admin(),
        token.get_sub(),
        token_manager,
    )
    .await
}

pub async fn revoke_my_session(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    claims: Claims,
) -> Result<impl IntoResponse, AppError> {
    revoke_session(state.get_db_pool(), *claims.get_jti()).await?;

    let cookie = create_cookie_session("", 0);
    let jar = jar.add(cookie);

    Ok((jar, StatusCode::NO_CONTENT))
}

pub async fn revoke_user_session(
    State(state): State<AppState>,
    Path(session_id): Path<Uuid>,
    claims: Claims,
) -> Result<impl IntoResponse, AppError> {
    check_admin(&claims)?;

    debug_assert!(session_id != Uuid::nil(), "Session ID cannot be nil");

    let session = get_session_by_id(state.get_db_pool(), session_id)
        .await?
        .ok_or_else(|| {
            tracing::debug!("Session {} not found in database", session_id);
            AppError::new(
                StatusCode::NOT_FOUND,
                format!("Session {} not found", session_id),
            )
        })?;
    tracing::debug!("Found session {} for user {}", session_id, session.user_id);

    if session.is_revoked {
        tracing::debug!("Session {} is already revoked", session_id);
        return Err(AppError::new(
            StatusCode::CONFLICT,
            format!("Session {} is already revoked", session_id),
        ));
    }

    if session.is_expired() {
        tracing::debug!("Session {} has expired", session_id);
        return Err(AppError::new(
            StatusCode::GONE,
            format!("Session {} has expired", session_id),
        ));
    }

    tracing::debug!("Revoking session {}", session_id);
    revoke_session_by_id(state.get_db_pool(), session_id).await?;

    debug_assert!(
        {
            let revoked_session = get_session_by_id(state.get_db_pool(), session_id)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to verify session revocation: {}", e);
                    AppError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to verify session revocation: {}", e),
                    )
                })?
                .ok_or_else(|| {
                    tracing::error!("Session disappeared after revocation");
                    AppError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Session disappeared after revocation",
                    )
                })?;
            tracing::debug!("Successfully revoked session {}", session_id);
            revoked_session.is_revoked
        },
        "Session was not properly revoked"
    );

    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<impl IntoResponse, AppError> {
    check_admin(&claims)?;

    revoke_session(state.get_db_pool(), Uuid::nil()).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_stale_sessions(
    state: &AppState,
    user_id: Uuid,
    is_admin: bool,
    sub: &str,
    token_manager: TokenManager<'_>,
) -> Result<SuccessResponse<AccessTokenResDto>, AppError> {
    if let Some(session) = get_session_by_user_id(state.get_db_pool(), user_id).await? {
        if session.is_expired() || session.is_revoked {
            delete_session_by_user_id(state.get_db_pool(), session.user_id).await?;
            return Err(AppError::new(StatusCode::UNAUTHORIZED, "Invalid token"));
        } else {
            let duration = Duration::seconds(
                *state
                    .get_config()
                    .get_jwt()
                    .get_access_token_expiration_secs(),
            );
            let (access_token, access_claims) =
                token_manager.create_access_token(session.user_id, sub, is_admin, duration)?;

            return Ok(SuccessResponse::created(AccessTokenResDto {
                access_token,
                access_token_expires_at: *access_claims.get_exp(),
            }));
        }
    }

    Err(AppError::new(StatusCode::UNAUTHORIZED, "Invalid token"))
}

pub async fn list_all_sessions(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<SuccessResponse<Vec<SessionResDto>>, AppError> {
    check_admin(&claims)?;

    let sessions = list_active_sessions(state.get_db_pool()).await?;
    Ok(SuccessResponse::ok(
        sessions.into_iter().map(SessionResDto::from).collect(),
    ))
}

pub async fn list_my_sessions(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<SuccessResponse<Vec<SessionResDto>>, AppError> {
    let sessions = list_user_active_sessions(state.get_db_pool(), *claims.get_jti()).await?;
    Ok(SuccessResponse::ok(
        sessions.into_iter().map(SessionResDto::from).collect(),
    ))
}
