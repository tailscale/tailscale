# nardump

nardump is like nix-store --dump, but in Go, writing a NAR file (tar-like,
but focused on being reproducible) to stdout or to a hash with the --sri flag.

It lets us calculate the Nix sha256 in shell.nix without the person running
git-pull-oss.sh having Nix available.
