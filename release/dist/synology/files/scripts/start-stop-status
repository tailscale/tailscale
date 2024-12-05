#!/bin/bash

SERVICE_NAME="tailscale"

if [ "${SYNOPKG_DSM_VERSION_MAJOR}" -eq "6" ]; then
    PKGVAR="/var/packages/Tailscale/etc"
else
    PKGVAR="${SYNOPKG_PKGVAR}"
fi

PID_FILE="${PKGVAR}/tailscaled.pid"
LOG_FILE="${PKGVAR}/tailscaled.stdout.log"
STATE_FILE="${PKGVAR}/tailscaled.state"
SOCKET_FILE="${PKGVAR}/tailscaled.sock"
PORT="41641"

SERVICE_COMMAND="${SYNOPKG_PKGDEST}/bin/tailscaled \
--state=${STATE_FILE} \
--socket=${SOCKET_FILE} \
--port=$PORT"

if [ "${SYNOPKG_DSM_VERSION_MAJOR}" -eq "7" -a ! -e "/dev/net/tun" ]; then
    # TODO(maisem/crawshaw): Disable the tun device in DSM7 for now.
    SERVICE_COMMAND="${SERVICE_COMMAND} --tun=userspace-networking"
fi

if [ "${SYNOPKG_DSM_VERSION_MAJOR}" -eq "6" ]; then
    chown -R tailscale:tailscale "${PKGVAR}/"
fi

start_daemon() {
    local ts=$(date --iso-8601=second)
    echo "${ts} Starting ${SERVICE_NAME} with: ${SERVICE_COMMAND}" >${LOG_FILE}
    STATE_DIRECTORY=${PKGVAR} ${SERVICE_COMMAND} 2>&1 | sed -u '1,200p;201s,.*,[further tailscaled logs suppressed],p;d' >>${LOG_FILE} &
    # We pipe tailscaled's output to sed, so "$!" retrieves the PID of sed not tailscaled.
    # Use jobs -p to retrieve the PID of the most recent process group leader.
    jobs -p >"${PID_FILE}"
}

stop_daemon() {
    if [ -r "${PID_FILE}" ]; then
        local PID=$(cat "${PID_FILE}")
        local ts=$(date --iso-8601=second)
        echo "${ts} Stopping ${SERVICE_NAME} service PID=${PID}" >>${LOG_FILE}
        kill -TERM $PID >>${LOG_FILE} 2>&1
        wait_for_status 1 || kill -KILL $PID >>${LOG_FILE} 2>&1
        rm -f "${PID_FILE}" >/dev/null
    fi
}

daemon_status() {
    if [ -r "${PID_FILE}" ]; then
        local PID=$(cat "${PID_FILE}")
        if ps -o pid -p ${PID} > /dev/null; then
            return
        fi
        rm -f "${PID_FILE}" >/dev/null
    fi
    return 1
}

wait_for_status() {
    # 20 tries
    # sleeps for 1 second after each try
    local counter=20
    while [ ${counter} -gt 0 ]; do
        daemon_status
        [ $? -eq $1 ] && return
        counter=$((counter - 1))
        sleep 1
    done
    return 1
}

ensure_tun_created() {
    if [ "${SYNOPKG_DSM_VERSION_MAJOR}" -eq "7" ]; then
        # TODO(maisem/crawshaw): Disable the tun device in DSM7 for now.
        return
    fi
    # Create the necessary file structure for /dev/net/tun
    if ([ ! -c /dev/net/tun ]); then
        if ([ ! -d /dev/net ]); then
            mkdir -m 755 /dev/net
        fi
        mknod /dev/net/tun c 10 200
        chmod 0755 /dev/net/tun
    fi

    # Load the tun module if not already loaded
    if (!(lsmod | grep -q "^tun\s")); then
        insmod /lib/modules/tun.ko
    fi
}

case $1 in
start)
    if daemon_status; then
        exit 0
    else
        ensure_tun_created
        start_daemon
        exit $?
    fi
    ;;
stop)
    if daemon_status; then
        stop_daemon
        exit $?
    else
        exit 0
    fi
    ;;
status)
    if daemon_status; then
        echo "${SERVICE_NAME} is running"
        exit 0
    else
        echo "${SERVICE_NAME} is not running"
        exit 3
    fi
    ;;
log)
    exit 0
    ;;
*)
    echo "command $1 is not implemented"
    exit 0
    ;;
esac
