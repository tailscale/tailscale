{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    go goimports gopls

    # keep this line if you use bash
    pkgs.bashInteractive
  ];
}
