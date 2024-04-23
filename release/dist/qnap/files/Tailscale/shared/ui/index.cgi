#!/bin/sh
CONF=/etc/config/qpkg.conf
QPKG_NAME="Tailscale"
QPKG_ROOT=$(/sbin/getcfg ${QPKG_NAME} Install_Path -f ${CONF} -d"")
exec "${QPKG_ROOT}/tailscale" --socket=/tmp/tailscale/tailscaled.sock web --cgi --prefix="/cgi-bin/qpkg/Tailscale/index.cgi/"
