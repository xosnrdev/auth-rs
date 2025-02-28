{
  description =
    "A lightweight and modular authentication service proof of concept (PoC) written in Rust.";
  inputs = {
    nixpkgs.url =
      "github:NixOS/nixpkgs?rev=a47b881e04af1dd6d414618846407b2d6c759380";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        manifest = pkgs.lib.importTOML ./Cargo.toml;
        package = manifest.package;
        # rustApp = pkgs.rustPlatform.buildRustPackage {
        #   pname = package.name;
        #   version = package.version;
        #   src = pkgs.lib.cleanSource ./.;
        #   cargoLock.lockFile = ./Cargo.lock;
        #   meta = with pkgs.lib; {
        #     inherit (package) description homepage repository;
        #     license = licenses.mit;
        #     maintainers = [ maintainers.xosnrdev ];
        #   };
        # };

        # Image author
        # author = "xosnrdev";
        # Container registry
        # registry = "ghcr.io";

        # Conditionally build Docker image only on Linux
        # (dockerTools can break on macOS, or cause flake check issues).
        # dockerImage = if pkgs.stdenv.isLinux then
        #   pkgs.dockerTools.buildImage {
        #     name = "${registry}/${author}/${rustApp.pname}-rs";
        #     tag = rustApp.version;
        #     created = "now";

        #     config = {
        #       Env = [
        #         "RUST_LOG=info"
        #         "APP__SERVER__HOST=0.0.0.0"
        #         "APP__SERVER__PORT=8080"
        #       ];
        #       Cmd = [ "${rustApp}/bin/${rustApp.pname}" ];
        #       Labels = {
        #         "org.opencontainers.image.title" = "${rustApp.pname}-rs";
        #         "org.opencontainers.image.version" = rustApp.version;
        #         "org.opencontainers.image.description" =
        #           rustApp.meta.description;
        #         "org.opencontainers.image.documentation" =
        #           rustApp.meta.homepage;
        #         "org.opencontainers.image.authors" = author;
        #         "org.opencontainers.image.source" = rustApp.meta.repository;
        #         "org.opencontainers.image.licenses" = "MIT";
        #       };
        #     };
        #   }
        # else
        # # If not Linux, set this to null so we can skip it.
        #   null;

        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.docker
            pkgs.sqlx-cli
            pkgs.cargo-watch
            pkgs.cargo-release
            pkgs.cargo-sort
            pkgs.cargo-audit
            pkgs.cargo-edit
            pkgs.git
          ];

          shellHook = ''
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
            echo "Starting Postgres container..."
            docker run --rm -d \
              --name postgres \
              -e POSTGRES_PASSWORD=$PGPASSWORD \
              -p 5432:5432 \
              postgres:17.3-alpine3.21
            function end {
              echo "Stopping Postgres container..."
              docker kill postgres 2>/dev/null || true
            }
            trap end EXIT
            sleep 3
            sqlx migrate run || {
              echo "Migration failed—check if Postgres container is running."
            }
          '';
        };

      in {
        # packages = if dockerImage == null then {
        #   default = rustApp;
        # } else {
        #   default = rustApp;
        #   docker = dockerImage;
        # };

        formatter = pkgs.nixfmt-classic;
        devShells.default = devShell;
      });
}
