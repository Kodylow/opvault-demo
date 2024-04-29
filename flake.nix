{
  inputs = {
    nixpkgs = { url = "github:nixos/nixpkgs/nixos-unstable"; };
    flake-utils = { url = "github:numtide/flake-utils"; };
  };
  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        bitcoindCustom = pkgs.bitcoind.overrideAttrs (prev: {
          src = pkgs.fetchFromGitHub {
            owner = "benthecarman";
            repo = "bitcoin";
            rev = "f036909dbe288ee5b7f2c38564a3c5375255822f";
            sha256 = "<correct-sha256>";
          };
        });
      in rec {
        devShell =
          pkgs.mkShell { buildInputs = with pkgs; [ python3 bitcoindCustom ]; };
      });
}
