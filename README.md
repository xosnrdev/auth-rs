# auth-rs

A lightweight and modular authentication service proof of concept (PoC) written in Rust.

## Features

- JWT-based authentication with access and refresh token support.
- Secure password hashing for user accounts.
- Role-based access control (RBAC) with support for admin and user roles.
- Revocable session management with token expiration handling.
- Middleware for CORS, rate limiting, and timeouts for production-ready APIs.
- Comprehensive configuration options for server, database, and environment settings.

## Requirements

- [Nix](https://determinate.systems/nix-installer/) for our reproducible development environment.
- [Docker](https://www.docker.com/) for spinning up a PostgreSQL instance.

## General Workflow

### Setup Environment

1. Enter the Development Shell:
   Run the following command to bootstrap everything:

   ```bash
   nix develop
   ```

   This will:

   - Set up all necessary Rust development tools (e.g., `rustc`, `cargo`, `clippy`, `rustfmt`).
   - Spin up an ephemeral PostgreSQL instance in Docker.
   - Execute database migrations automatically using SQLx.

2. Run the Development Server:
   After entering the shell, start the application:

   ```bash
   cargo run
   ```

   The server will be accessible at `http://127.0.0.1:8080` by default.

### Environment Variables

See the `.env.example` file for a list of configurable environment variables.

## API Documentation

See the [API Documentation](docs/API.md) for a list of available endpoints and example requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
