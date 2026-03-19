# $1 == 0 for uninstallation.
# $1 == 1 for removing old package during upgrade.

systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    systemctl stop tailscale.nginx-auth.service >/dev/null 2>&1 || :
    systemctl try-restart tailscale.nginx-auth.socket >/dev/null 2>&1 || :
fi
