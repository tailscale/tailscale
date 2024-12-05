#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
	  if [ -d /run/systemd/system ]; then
		    deb-systemd-invoke stop 'tailscale.nginx-auth.service' >/dev/null || true
		    deb-systemd-invoke stop 'tailscale.nginx-auth.socket' >/dev/null || true
	  fi
fi
