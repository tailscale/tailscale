#!/usr/bin/env sh
set -eu

eval $(brew/vars.sh)

GIT_URL=https://github.com/tailscale/tailscale.git
BRANCH=main
VERSION=$TS_VER # TODO(mkramlich): WIP. do this right

# default formula (pinned against a commmit in the Tailscale GitHub repo)
FORMULA_TYPE=commit URL=$GIT_URL BRANCH=$BRANCH REVISION=$TS_COMMIT_PIN HEAD=$GIT_URL BRANCH=$BRANCH VERSION=$VERSION brew/generate-formula.sh > brew/tailscale.commit-pin.rb

# alt formula using local HTTP source tarball of a release standin/mock
FORMULA_TYPE=tarball URL="http://localhost:$TS_TARBALL_PORT/tailscale/tailscale/archive/v1.5.0.tar.gz" SHA256="a62caf2eb5c84d2d1775cd8a17eeb0e8ad3b8dbc9453399862d908227e0af721" HEAD=$GIT_URL BRANCH=$BRANCH VERSION=$VERSION brew/generate-formula.sh > brew/tailscale.tb-local.rb

# alt formula using Tailscale GitHub HTTPS source tarball of a release tag -- the LATEST tag
FORMULA_TYPE=tarball URL="https://github.com/tailscale/tailscale/archive/v1.4.4.tar.gz" SHA256="5312c6d075a32049912e0932a89269869def9ac8ea9d0fdccc6b41db60fc2d4c" HEAD=$GIT_URL BRANCH=$BRANCH VERSION=$VERSION brew/generate-formula.sh > brew/tailscale.tb-github.rb

cp brew/tailscale{.commit-pin,}.rb
