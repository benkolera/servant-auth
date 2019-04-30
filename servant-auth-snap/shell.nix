let
  nixpkgs = import ((import <nixpkgs> {}).fetchFromGitHub {
    repo = "nixpkgs-channels";
    owner = "NixOS";
    rev   = "1d36ad6d16dbf1d3937f899a087a4360332eb142";
    sha256 = "0rf1n61xlbvanrknh7g9884qjy6wmwc5x42by3f9vxqmfhz906sq";
  }) {};
in nixpkgs.haskellPackages.developPackage {
  root = ./.;
  overrides = hself: hsuper: {
    servant-auth-client = hself.callCabal2nix "servant-auth-client" ../servant-auth-client {};
    entropy = hself.callHackage "entropy" "0.4.1.3" {};
    http-types = hself.callHackage "http-types" "0.12.2" {};
    servant-snap = hself.callCabal2nix "servant-snap" (builtins.fetchGit {
      url = "https://github.com/antislava/servant-snap.git";
      rev = "3f899473a12890777caa226ab249498ab5442837";
    }) {};
  };
}
