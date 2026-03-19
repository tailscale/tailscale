if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ] ; then
	  deb-systemd-helper unmask 'tailscale.nginx-auth.socket' >/dev/null || true
	  if deb-systemd-helper --quiet was-enabled 'tailscale.nginx-auth.socket'; then
		    deb-systemd-helper enable 'tailscale.nginx-auth.socket' >/dev/null || true
	  else
		    deb-systemd-helper update-state 'tailscale.nginx-auth.socket' >/dev/null || true
	  fi

    if systemctl is-active tailscale.nginx-auth.socket >/dev/null; then
        systemctl --system daemon-reload >/dev/null || true
        deb-systemd-invoke stop 'tailscale.nginx-auth.service' >/dev/null || true
        deb-systemd-invoke restart 'tailscale.nginx-auth.socket' >/dev/null || true
    fi
fi
