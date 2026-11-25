{
  description = "ipv6ddns: DNS names for every device on your network, on the LAN and on the internet, wherever its addresses move";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Where the command runs, of the systems nixpkgs has.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # A flake knows its commit, not its tag: the version is the commit's.
      version = self.shortRev or self.dirtyShortRev or "dev";
      package = pkgs: pkgs.callPackage ./nix/package.nix { inherit version; };
    in
    {
      packages = forEachSystem (pkgs: rec {
        ipv6ddns = package pkgs;
        default = ipv6ddns;
      });

      overlays.default = final: _prev: { ipv6ddns = package final; };

      # services.ipv6ddns, for NixOS.
      nixosModules.default = import ./nix/module.nix self;

      # nix flake check: the package builds, which tells a hash of the modules that is behind
      # go.sum, and on Linux the service of the module runs in a machine of NixOS, and discovers
      # another on its network.
      checks = forEachSystem (
        pkgs:
        {
          package = package pkgs;
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          module = import ./nix/test.nix { inherit pkgs self; };
        }
      );

      formatter = forEachSystem (pkgs: pkgs.nixfmt-rfc-style);
    };
}
