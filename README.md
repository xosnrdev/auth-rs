# auth-rs

A lightweight and modular authentication service proof of concept (PoC) written in Rust.

## Features

[x] JWT Authentication
   - Access and refresh tokens
   - Role-based access control
   - Session management

[x] Security
   - Password hashing
   - Token expiration
   - Session revocation
   - CORS middleware
   - Rate limiting
   - Request timeouts
   - Environment config

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.85.0 or later (using Rust 2024 edition)
- [Nix](https://determinate.systems/nix-installer/) for reproducible development environment
- [Docker](https://www.docker.com/) for PostgreSQL database

## Quick Start

1. Enter development shell:
   ```bash
   nix develop
   ```

2. Start the server:
   ```bash
   cargo run
   ```
   Server runs at `http://127.0.0.1:8080` by default.

## Configuration

Copy `.env.example` to `.env` and adjust the values:
```bash
cp .env.example .env
```

## Documentation

- [API Documentation](docs/API.md) - Available endpoints and examples

## License

[MIT](LICENSE)