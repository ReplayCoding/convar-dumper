{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };
  outputs = {
    self,
    nixpkgs,
  }: let
    forSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
  in {
    devShells = forSystems (
      system: let
        pkgs_ = import nixpkgs {
          localSystem.system = system;
          crossSystem.system = "i686-linux";
        };
        pkgs = pkgs_.__splicedPackages;
      in {
        default = pkgs.stdenv.mkDerivation {
          name = "devshell";
          nativeBuildInputs = with pkgs; [
            # For build
            cmake
            ninja
            pkg-config

            lldb
          ];
          buildInputs = with pkgs; [
          ];
        };
      }
    );
  };
}
