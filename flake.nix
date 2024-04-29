{
  description = "Application packaged using poetry2nix";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # poetryOverrides = self: super: {
        #   dulwich = super.dulwich.overrideAttrs (oldAttrs: rec {
        #     version = "0.21.2";
        #     src = pkgs.fetchPypi {
        #       pname = "dulwich";
        #       inherit version;
        #       sha256 = "0kqd3f7rgmyzsbwjwqx9zcbi7c3m2zzq8rss6k768za9v5zswrfq";
        #     };
        #   });
        # };
        inherit (poetry2nix.lib.mkPoetry2Nix { inherit pkgs; })
          mkPoetryApplication;

        bitcoindMutinynet = pkgs.bitcoind.overrideAttrs (prev: {
          src = pkgs.fetchFromGitHub {
            owner = "benthecarman";
            repo = "bitcoin";
            rev = "f036909dbe288ee5b7f2c38564a3c5375255822f";
            sha256 = "BBkAkupvDjomSQxiM+yeGi7N2boq7ga4q5Ij0+6yWkY=";
          };
        });

      in {
        packages = {
          myapp = mkPoetryApplication { projectDir = self; };
          default = self.packages.${system}.myapp;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.myapp ];
          packages = [ pkgs.poetry bitcoindMutinynet ];
          shellHook = ''
            echo "Starting bitcoind on mutinynet..."
            mkdir -p $PWD/bitcoin_datadir
            ${bitcoindMutinynet}/bin/bitcoind -datadir=$PWD/bitcoin_datadir -signet -daemon \
              -rpcbind=0.0.0.0 -fallbackfee=0.00008 \
              -signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae \
              -addnode=mutinynet-upstream.dev.fedibtc.com:38333 \
              -addnode=public.mutinynet-bitcoind-01.dev.fedibtc.com:38333 \
              -dnsseed=0 -signetblocktime=30 -rpcallowip=0.0.0.0/0 -prune=550
            export BITCOIN_CLI="${bitcoindMutinynet}/bin/bitcoin-cli -datadir=$PWD/bitcoin_datadir -signet"
            alias bitcoin-cli="$BITCOIN_CLI"
            echo "bitcoind started and bitcoin-cli alias set."
          '';
        };
      });
}
