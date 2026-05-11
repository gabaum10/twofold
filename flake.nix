{
  description = "twofold — one document, two views";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "twofold";
          version = "0.3.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # rusqlite with bundled feature needs these at build time
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.sqlite pkgs.openssl ];

          meta = with pkgs.lib; {
            description = "One document, two views. Markdown share service for humans and agents.";
            homepage = "https://github.com/gabaum10/twofold";
            license = licenses.mit;
            mainProgram = "twofold";
          };
        };
      }
    );
}
