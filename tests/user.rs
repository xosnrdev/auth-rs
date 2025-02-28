use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use auth_rs::{
    dto::{LoginReqDto, LoginResDto, UserReqDto, UserResDto},
    utils::{AppResult, SuccessResponse},
};

mod common;
use common::ctx;

// Test fixtures
struct TestUser {
    username: String,
    email: String,
    password: String,
    avatar_url: Option<String>,
    github_id: Option<i64>,
    access_token: Option<String>,
}

impl Default for TestUser {
    fn default() -> Self {
        Self {
            username: format!("usr_{}", Uuid::new_v4().as_u128() % 1000000),
            email: format!("test_{}@example.com", Uuid::new_v4()),
            password: "Test123!@#".to_string(),
            avatar_url: None,
            github_id: None,
            access_token: None,
        }
    }
}

impl TestUser {
    fn with_username(mut self, username: &str) -> Self {
        self.username = username.to_string();
        self
    }

    fn with_email(mut self, email: &str) -> Self {
        self.email = email.to_string();
        self
    }

    fn with_password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    fn to_register_dto(&self) -> UserReqDto {
        UserReqDto {
            username: Some(self.username.clone()),
            email: Some(self.email.clone()),
            password: self.password.clone(),
            avatar_url: self.avatar_url.clone(),
            github_id: self.github_id,
        }
    }

    fn to_login_dto(&self) -> LoginReqDto {
        LoginReqDto {
            username: Some(self.username.clone()),
            email: Some(self.email.clone()),
            password: self.password.clone(),
        }
    }
}

// Helper functions
async fn register_user(app: &mut Router, user: &TestUser) -> Result<SuccessResponse<UserResDto>> {
    let req = Request::builder()
        .uri("/users/register")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&user.to_register_dto())?))?;

    let res = app.oneshot(req).await?;
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await?;

    if status != StatusCode::CREATED {
        anyhow::bail!(
            "Failed to register user: {:?}",
            String::from_utf8_lossy(&body)
        );
    }

    Ok(serde_json::from_slice(&body)?)
}

async fn login_user(app: &mut Router, user: &mut TestUser) -> Result<SuccessResponse<LoginResDto>> {
    let req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&user.to_login_dto())?))?;

    let res = app.oneshot(req).await?;
    let status = res.status();
    let body = to_bytes(res.into_body(), usize::MAX).await?;

    if status != StatusCode::CREATED {
        anyhow::bail!("Failed to login user: {:?}", String::from_utf8_lossy(&body));
    }

    let login_res: SuccessResponse<LoginResDto> = serde_json::from_slice(&body)?;
    user.access_token = Some(login_res.body.access_token.clone());
    Ok(login_res)
}

async fn get_user_profile(app: &mut Router, user: &TestUser) -> Result<Response<Body>> {
    let req = Request::builder()
        .uri("/users/me")
        .method("GET")
        .header("Content-Type", "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", user.access_token.as_ref().unwrap()),
        )
        .body(Body::empty())?;

    Ok(app.oneshot(req).await?)
}

async fn update_user_profile(
    app: &mut Router,
    user: &TestUser,
    update: serde_json::Value,
) -> Result<Response<Body>> {
    let req = Request::builder()
        .uri("/users/me")
        .method("PATCH")
        .header("Content-Type", "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", user.access_token.as_ref().unwrap()),
        )
        .body(Body::from(update.to_string()))?;

    Ok(app.oneshot(req).await?)
}

async fn delete_user_profile(app: &mut Router, user: &TestUser) -> Result<Response<Body>> {
    let req = Request::builder()
        .uri("/users/me")
        .method("DELETE")
        .header("Content-Type", "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", user.access_token.as_ref().unwrap()),
        )
        .body(Body::empty())?;

    Ok(app.oneshot(req).await?)
}

// Registration Tests
#[sqlx::test]
async fn test_successful_user_registration(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let test_user = TestUser::default();

    let res = register_user(&mut app, &test_user).await?;

    assert_eq!(res.status as u16, StatusCode::CREATED.as_u16());
    assert_eq!(res.body.username, test_user.username.to_lowercase());
    assert_eq!(res.body.email, test_user.email.to_lowercase());
    assert!(!res.body.is_admin);
    assert_eq!(res.body.avatar_url, None);
    assert_eq!(res.body.github_id, None);

    Ok(())
}

#[sqlx::test]
async fn test_duplicate_username_registration(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let test_user = TestUser::default();

    // Register first user
    register_user(&mut app, &test_user).await?;

    // Try to register second user with same username
    let duplicate_user = TestUser::default().with_username(&test_user.username);

    let req = Request::builder()
        .uri("/users/register")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(
            &duplicate_user.to_register_dto(),
        )?))?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    Ok(())
}

#[sqlx::test]
async fn test_invalid_email_registration(db_pool: PgPool) -> AppResult<()> {
    let app = ctx(db_pool)?;
    let test_user = TestUser::default().with_email("invalid-email");

    let req = Request::builder()
        .uri("/users/register")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(
            &test_user.to_register_dto(),
        )?))?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

#[sqlx::test]
async fn test_weak_password_registration(db_pool: PgPool) -> AppResult<()> {
    let app = ctx(db_pool)?;
    let test_user = TestUser::default().with_password("weak");

    let req = Request::builder()
        .uri("/users/register")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(
            &test_user.to_register_dto(),
        )?))?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

// Login Tests
#[sqlx::test]
async fn test_successful_user_login(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let mut test_user = TestUser::default();

    // Register user
    register_user(&mut app, &test_user).await?;

    // Login user
    let login_res = login_user(&mut app, &mut test_user).await?;

    assert_eq!(login_res.status as u16, StatusCode::CREATED.as_u16());
    assert!(!login_res.body.session_id.is_nil());
    assert!(!login_res.body.access_token.is_empty());
    assert!(!login_res.body.refresh_token.is_empty());
    assert_eq!(login_res.body.access_token_expires_at, 900);
    assert_eq!(login_res.body.refresh_token_expires_at, 86400);
    assert_eq!(
        login_res.body.user.username,
        test_user.username.to_lowercase()
    );
    assert_eq!(login_res.body.user.email, test_user.email.to_lowercase());

    Ok(())
}

#[sqlx::test]
async fn test_login_with_wrong_password(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let test_user = TestUser::default();

    // Register user
    register_user(&mut app, &test_user).await?;

    // Try to login with wrong password
    let wrong_password_user = TestUser::default()
        .with_username(&test_user.username)
        .with_email(&test_user.email)
        .with_password("WrongPass123!");

    let req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(
            &wrong_password_user.to_login_dto(),
        )?))?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[sqlx::test]
async fn test_login_nonexistent_user(db_pool: PgPool) -> AppResult<()> {
    let app = ctx(db_pool)?;
    let test_user = TestUser::default();

    let req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(
            &test_user.to_login_dto(),
        )?))?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

// Profile Tests
#[sqlx::test]
async fn test_get_own_profile(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let mut test_user = TestUser::default();

    // Register and login user
    register_user(&mut app, &test_user).await?;
    login_user(&mut app, &mut test_user).await?;

    // Get profile
    let res = get_user_profile(&mut app, &test_user).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let profile: SuccessResponse<UserResDto> = serde_json::from_slice(&body)?;

    assert_eq!(profile.body.username, test_user.username.to_lowercase());
    assert_eq!(profile.body.email, test_user.email.to_lowercase());

    Ok(())
}

#[sqlx::test]
async fn test_update_profile(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let mut test_user = TestUser::default();

    // Register and login user
    register_user(&mut app, &test_user).await?;
    login_user(&mut app, &mut test_user).await?;

    // Update profile
    let new_username = format!("updated_{}", Uuid::new_v4().as_u128() % 1000000);
    let update = json!({
        "username": new_username,
        "avatar_url": "https://example.com/avatar.jpg"
    });

    let res = update_user_profile(&mut app, &test_user, update).await?;
    assert_eq!(res.status(), StatusCode::OK);

    let body = to_bytes(res.into_body(), usize::MAX).await?;
    let updated: SuccessResponse<UserResDto> = serde_json::from_slice(&body)?;

    assert_eq!(updated.body.username, new_username.to_lowercase());
    assert_eq!(
        updated.body.avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );

    Ok(())
}

#[sqlx::test]
async fn test_delete_profile(db_pool: PgPool) -> AppResult<()> {
    let mut app = ctx(db_pool)?;
    let mut test_user = TestUser::default();

    // Register and login user
    register_user(&mut app, &test_user).await?;
    login_user(&mut app, &mut test_user).await?;

    // Delete profile
    let res = delete_user_profile(&mut app, &test_user).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Try to get profile after deletion
    let res = get_user_profile(&mut app, &test_user).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[sqlx::test]
async fn test_unauthorized_profile_access(db_pool: PgPool) -> AppResult<()> {
    let app = ctx(db_pool)?;

    // Try to get profile without login
    let req = Request::builder()
        .uri("/users/me")
        .method("GET")
        .header("Content-Type", "application/json")
        .body(Body::empty())?;

    let res = app.oneshot(req).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
