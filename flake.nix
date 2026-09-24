{
  description = "tpt-privd — privileged command daemon (I7 flake)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Sibling path dependency (crates/tpt-privd-daemon → tpt-l-sandbox).
    # Keep this input in sync with the Cargo path and CI checkout.
    tpt-linux-sandbox = {
      url = "github:TPT-Solutions/tpt-linux-sandbox";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, tpt-linux-sandbox }:
    flake-utils.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        # Rebuild the tree so the relative path dep resolves inside the store:
        #   src/tpt-privd + src/tpt-linux-sandbox
        src = pkgs.runCommand "tpt-privd-src" { } ''
          mkdir -p $out
          cp -r ${self} $out/tpt-privd
          chmod -R u+w $out/tpt-privd
          cp -r ${tpt-linux-sandbox} $out/tpt-linux-sandbox
          chmod -R u+w $out/tpt-linux-sandbox
          # The flake source is the tpt-privd repo root; Cargo expects the
          # workspace at the top of $out/tpt-privd.
        '';
        # Prefer crane/rustPlatform if present; plain buildRustPackage with
        # cargoLock is the portable fallback for a path-dep workspace.
        tpt-privd = pkgs.rustPlatform.buildRustPackage {
          pname = "tpt-privd";
          version = "0.1.0";
          src = "${src}/tpt-privd";
          # buildRustPackage needs the sibling visible relative to src.
          # We set cargoRoot / postPatch to re-link.
          postPatch = ''
            ln -sfn ${src}/tpt-linux-sandbox ../tpt-linux-sandbox
          '';
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
          # Unit tests that need /tmp write access are fine in the sandbox;
          # Unix-socket integration tests run here on Linux.
          doCheck = true;
          meta = with pkgs.lib; {
            description = "Privileged command daemon for tpt-privd";
            homepage = "https://github.com/TPT-Solutions/tpt-privd";
            license = with licenses; [ mit apache2 ];
            platforms = platforms.linux;
          };
        };
      in
      {
        packages.default = tpt-privd;
        packages.tpt-privd = tpt-privd;

        checks = {
          inherit tpt-privd;
          # `nix flake check` also builds the default package (tests run).
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            pkg-config
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });
}
