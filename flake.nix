{
  description = "Auth Service PoC in Rust";

  # ----------------------------------------------------------------------------
  # Inputs
  # ----------------------------------------------------------------------------
  inputs = {
    # Using a pinned nixpkgs reference for consistency
    nixpkgs.url =
      "github:NixOS/nixpkgs?rev=de1864217bfa9b5845f465e771e0ecb48b30e02d";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # ----------------------------------------------------------------------------
  # Outputs
  # ----------------------------------------------------------------------------
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        manifest = pkgs.lib.importTOML ./Cargo.toml;
        package = manifest.package;

        # ----------------------------------------------------------------------
        # Rust Build
        # ----------------------------------------------------------------------
        rustApp = pkgs.rustPlatform.buildRustPackage {
          pname = package.name;
          version = package.version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;

          checkFlags = [
            # Skip tests that require a running Postgres instance
            "--skip=test_health_check"
            "--skip=test_user"
          ];
          meta = with pkgs.lib; {
            inherit (package) description homepage repository;
            license = licenses.mit;
            maintainers = [ maintainers.xosnrdev ];
          };
        };

        # Image author
        author = "xosnrdev";
        # Container registry
        registry = "ghcr.io";

        # ----------------------------------------------------------------------
        # Conditionally build Docker image only on Linux
        # (dockerTools can break on macOS, or cause flake check issues).
        # ----------------------------------------------------------------------
        dockerImage = if pkgs.stdenv.isLinux then
          pkgs.dockerTools.buildImage {
            name = "${registry}/${author}/${rustApp.pname}-rs";
            tag = rustApp.version;
            created = "now";

            config = {
              Env = [
                "RUST_LOG=info"
                "APP__SERVER__HOST=0.0.0.0"
                "APP__SERVER__PORT=8080"
              ];
              Cmd = [ "${rustApp}/bin/${rustApp.pname}" ];
              Labels = {
                "org.opencontainers.image.title" = "${rustApp.pname}-rs";
                "org.opencontainers.image.version" = rustApp.version;
                "org.opencontainers.image.description" =
                  rustApp.meta.description;
                "org.opencontainers.image.documentation" =
                  rustApp.meta.homepage;
                "org.opencontainers.image.authors" = author;
                "org.opencontainers.image.source" = rustApp.meta.repository;
                "org.opencontainers.image.licenses" = "MIT";
              };
            };
          }
        else
        # If not Linux, set this to null so we can skip it.
          null;

        # ----------------------------------------------------------------------
        # Development Shell (Ephemeral Postgres in Docker)
        #
        # Instead of managing a local Postgres with `initdb` and manual traps,
        # we spin up a Docker container with `--rm`, guaranteeing ephemeral data
        # once stopped—solving the real need (X) rather than relying on a fragile
        # EXIT trap for local Postgres (Y).
        # ----------------------------------------------------------------------
        devShell = pkgs.mkShell {
          buildInputs = [
            # Docker needed to spin up ephemeral containers
            pkgs.docker

            # Rust & dev tooling
            pkgs.sqlx-cli
            pkgs.cargo-watch
            pkgs.git-cliff
            pkgs.cargo-release
            pkgs.cargo-sort
            pkgs.cargo-deny
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
          ];

          shellHook = ''
            # ------------------------------------------------------------------
            # Environment variables for your Auth Service
            # ------------------------------------------------------------------
            export RUST_BACKTRACE=1
            export RUST_LOG=debug

            PGDATABASE=postgres
            PGUSER=postgres
            PGPASSWORD=password
            PGPORT=5432
            PGHOST=localhost

            export DATABASE_URL=postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE
            export APP__DATABASE__USERNAME=$PGUSER
            export APP__DATABASE__PASSWORD=$PGPASSWORD
            export APP__DATABASE__HOST=$PGHOST
            export APP__DATABASE__PORT=$PGPORT
            export APP__DATABASE__NAME=$PGDATABASE
            export APP__DATABASE__MAX_CONNECTIONS=10
            export APP__DATABASE__MIN_CONNECTIONS=1
            export APP__DATABASE__ACQUIRE_TIMEOUT_SECS=5

            export APP__SERVER__HOST=127.0.0.1
            export APP__SERVER__PORT=8080
            export APP__SERVER__TIMEOUT_IN_SECS=10
            export APP__SERVER__ORIGINS=http://localhost:3000
            export APP__SERVER__RATE_LIMIT_PER_SECS=100
            export APP__SERVER__RATE_LIMIT_BURST=10
            export APP__SERVER__COOKIE_SECRET=$(openssl rand -base64 64)

            export APP__ENVIRONMENT=local

            export APP__JWT__SECRET=$(openssl rand -base64 64)
            export APP__JWT__ACCESS_TOKEN_EXPIRATION_SECS=900
            export APP__JWT__REFRESH_TOKEN_EXPIRATION_SECS=86400

            # ------------------------------------------------------------------
            # Start ephemeral Docker Postgres
            # --rm ensures the container is removed once stopped.
            # ------------------------------------------------------------------
            echo "Starting ephemeral Postgres container..."
            docker run --rm -d \
              --name ephemeral-postgres \
              -e POSTGRES_PASSWORD=$PGPASSWORD \
              -p 5432:5432 \
              postgres:latest

            # Cleanup trap: kill the container on shell exit.
            function end {
              echo "Stopping ephemeral Postgres container..."
              docker kill ephemeral-postgres 2>/dev/null || true
            }
            trap end EXIT

            # Give the container a few seconds to spin up
            sleep 3

            # Run migrations
            sqlx migrate run || {
              echo "Migration failed—check if Postgres container is running."
            }
          '';
        };

      in {
        # --------------------------------------------------------------------
        # Provide `default` (Rust app) on all systems
        # Only provide `docker` if `dockerImage` is not null (i.e., Linux)
        # --------------------------------------------------------------------
        packages = if dockerImage == null then {
          default = rustApp;
        } else {
          default = rustApp;
          docker = dockerImage;
        };

        # Formatter
        formatter = pkgs.nixfmt-classic;

        # Development Shell
        devShells.default = devShell;

        # --------------------------------------------------------------------
        # XY Problem Documentation
        # --------------------------------------------------------------------
        # We once tried hooking a local Postgres DB (with `initdb` and `pg_ctl`) 
        # to the Nix shell lifecycle, relying on an EXIT trap to clean up. 
        # However, that trap was fragile (e.g., not always triggered if the shell
        # closed abruptly), leaving leftover processes or data. This was a 
        # textbook XY problem:
        #
        #   - X: "We need an ephemeral, consistent Postgres instance for dev 
        #         that doesn't linger once the shell exits."
        #   - Y: "Let's embed local Postgres lifecycle logic in shellHook 
        #         and rely on a shell trap for cleanup."
        #
        # By focusing on the real need (X)—ephemeral DB state—rather than 
        # a complicated local Postgres approach (Y), we replaced it with Docker 
        # containers using `--rm`, ensuring Postgres is ephemeral by design. 
        # This approach also makes flake checks simpler across platforms:
        # 
        #   - On non-Linux systems, we skip building the Docker image 
        #     while still allowing Docker-based ephemeral Postgres if 
        #     the user has Docker installed.
        #
        # This eliminates leftover data and processes, solving the 
        # underlying problem far more robustly.
      });
}
