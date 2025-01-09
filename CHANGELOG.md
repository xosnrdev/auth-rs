# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-12-26

### Changed

- Update Docker image configuration and remove release notes script by @xosnrdev
- Release auth version 0.2.0 by @xosnrdev
- Clean up cargo toml by @xosnrdev
- Update CI workflows to run on nix environment by @xosnrdev
- Cleanup release workflow by @xosnrdev
- Consolidate all nix expression into flake.nix by @xosnrdev
- Refactor project structure and transition to Axum framework by @xosnrdev
  in [#17](https://github.com/xosnrdev/auth-rs/pull/17)

### Fixed

- Correct typos in .env.example and update pre-commit configuration by @xosnrdev

## [1.5.0] - 2024-11-01

### Added

- Add rate limiting configuration by @xosnrdev
- Add middlewares module and re-export the rate limit middleware by @xosnrdev
- Add Redis service to docker-compose.yml by @xosnrdev
- Add Redis configuration to .env.example by @xosnrdev

### Changed

- Release auth_rs version 1.5.0 by @xosnrdev
- Cleanup and weekly maintenance by @xosnrdev in [#16](https://github.com/xosnrdev/auth-rs/pull/16)
- Trim token before converting to string by @xosnrdev
- Merge pull request #15 from xosnrdev/feature/#12-session-management by @xosnrdev
  in [#15](https://github.com/xosnrdev/auth-rs/pull/15)
- Merge pull request #14 from xosnrdev/feature/#10-rate-limiting by @xosnrdev
  in [#14](https://github.com/xosnrdev/auth-rs/pull/14)
- Add rate limiting middleware and configuration by @xosnrdev
- Add rate limiting middleware by @xosnrdev
- Change token extraction to return a String instead of a &str by @xosnrdev
- Add RateLimitError conversion to AuthResponse by @xosnrdev
- Added actix limitation crate for ratelimit setup by @xosnrdev
- Add RateLimitConfig module and builder by @xosnrdev
- Merge pull request #13 from xosnrdev/feature/#12-session-management by @xosnrdev
  in [#13](https://github.com/xosnrdev/auth-rs/pull/13)
- Add RedisConfig module and builder. by @xosnrdev
- Add RedisConfig module and builder by @xosnrdev
- Update Cargo.toml to add redis crate dependency by @xosnrdev
- Remove unnecessary EXPOSE statement in Dockerfile by @xosnrdev
- Update SQLX_OFFLINE environment variable in Dockerfile by @xosnrdev
- Add Dockerfile for containerization by @xosnrdev
- Update docker-compose.yml for PostgreSQL configuration by @xosnrdev
- Update sqlx migrate command in README.md by @xosnrdev
- Update SSLMode to use PgSslMode enum by @xosnrdev
- Moved to sqlx default source file by @xosnrdev

## [1.0.0] - 2024-10-27

### Added

- Add .vscode/launch.json configuration file by @xosnrdev
- Added health check route handler by @xosnrdev

### Changed

- Release auth_rs version 1.0.0 by @xosnrdev
- Update Cargo.toml with readme and repository information by @xosnrdev
- Build optimization by @xosnrdev
- SQLx query cache for bypassing compile check by @xosnrdev
- Update branch name in GitHub Actions workflow by @xosnrdev
- Add GitHub Actions workflow for releasing the application by @xosnrdev
- Add GitHub Actions workflow for running tests by @xosnrdev
- Update field naming convention in README.md by @xosnrdev
- Update field naming convention in refresh_token.rs by @xosnrdev
- Update struct field naming convention in user.rs and user model by @xosnrdev
- Update refresh token parameter in token refresh API example by @xosnrdev
- Update users and refresh_tokens table in auth.sql migration by @xosnrdev
- Update refresh token parameter in token refresh API example by @xosnrdev
- Crate name to auth_rs by @xosnrdev
- Update project name and api design briefing by @xosnrdev
- Server and database configurations placeholder by @xosnrdev
- Update TokenDetails struct to use a non-optional refresh token by @xosnrdev
- Update logout and get_me methods to use access token instead of refresh token by @xosnrdev
- Update logout and get_me methods to use access token instead of refresh token by @xosnrdev
- Organize code structure and add controllers module by @xosnrdev
- Update server configuration and listener setup by @xosnrdev
- Remove serde_json dependency from Cargo.lock and Cargo.toml by @xosnrdev
- Add columns to users table and create refresh_tokens table by @xosnrdev
- Add email deserialization utility function by @xosnrdev
- Update AuthResponse, TokenDetails, and ErrorDetails structs by @xosnrdev
- UpdateEmailDto and UpdatePasswordDto structs by @xosnrdev
- Remove unnecessary CreateUserDto and LoginDto structs by @xosnrdev
- AuthServiceError and add TokenExtractError variant by @xosnrdev
- Fleshed out FromRequest trait actix web for TokenExtract by @xosnrdev
- Better auth service handling fleshed out of the box by @xosnrdev
- Fleshed out authentication controllers and routes logic by @xosnrdev
- Update dependencies: regex and serde_json by @xosnrdev
- Add AppState struct to hold application state and dependencies by @xosnrdev
- Add Debug trait to ServerConfig struct by @xosnrdev
- Remove unused Credentials struct from User module by @xosnrdev
- Update AuthService struct and methods to handle known auth edge cases by @xosnrdev
- Add JWT module and Services struct by @xosnrdev
- Update RefreshTokenService struct and methods by @xosnrdev
- Update UserService struct and methods by @xosnrdev
- Adjust service to partial rfc compliance by @xosnrdev
- Refactor auth and user DTO modules for improved consistency and validation by @xosnrdev
- Refactor AuthServiceError enum to include JWTServiceError and TokenExtractionError variants by @xosnrdev
- Add JWT token extraction utility module by @xosnrdev
- Refactor JWT module to use JWTService struct for improved clarity and consistency by @xosnrdev
- Refactor repository modules to use Arc<PgPool> for thread safety by @xosnrdev
- Add modules for authentication, tokens, users, and refresh tokens by @xosnrdev
- Add DTO modules for authentication, tokens, and users by @xosnrdev
- Add DTO module for authentication by @xosnrdev
- Added structured logging and error handling by @xosnrdev
- Small fix by @xosnrdev
- Updated future work by @xosnrdev
- Added centralized configuration for app state by @xosnrdev
- Remove duplicate by @xosnrdev
- MVP ready by @xosnrdev
- Restructure repository and service modules by @xosnrdev
- Did some changes and fixes by @xosnrdev
- I still don't know by @xosnrdev
- Fix skill issue by @xosnrdev
- Added known custom errors for now by @xosnrdev
- I don't know man by @xosnrdev

### Removed

- Removed unnecessary map_err by @xosnrdev
- Remove redundant some by @xosnrdev

## New Contributors

- @xosnrdev made their first contribution
  [0.2.0]: https://github.com/xosnrdev/auth-rs/compare/v1.5.0..v0.2.0
  [1.5.0]: https://github.com/xosnrdev/auth-rs/compare/v1.0.0..v1.5.0
