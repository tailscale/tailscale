redo-ifchange version-info.sh

. ./version-info.sh

cat >$3 <<EOF
#define TAILSCALE_VERSION_LONG "$VERSION_LONG"
#define TAILSCALE_VERSION_SHORT "$VERSION_SHORT"
#define TAILSCALE_VERSION_WIN_RES $VERSION_WINRES
EOF
