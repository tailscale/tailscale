#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# ec2-idle-stop.sh stops (doesn't terminate) the benchmark EC2 instances
# that ec2.sh creates, those tagged owner=claude-tswg, once they've been
# idle for a while, to keep costs down. "Idle" means the marker file
# $TSWG_EC2_MARKER (default ~/.cache/tslinux/ec2/last-used) hasn't been
# touched for $TSWG_EC2_IDLE_MINUTES (default 30) minutes: ec2.sh touches
# it on every command, and tailscale.com's lean harness touches it every
# minute while it uses the instances. Stopped instances keep their disks;
# "ec2.sh start" brings them back.
#
# It's meant to run every few minutes from a systemd user timer on a host
# that's always on:
#
#   ec2-idle-stop.sh install    install and start the timer (and enable lingering,
#                               so it runs without a login session)
#   ec2-idle-stop.sh uninstall  remove the timer
#   ec2-idle-stop.sh check      stop the instances if idle (what the timer runs)

set -eu

export AWS_PROFILE=${AWS_PROFILE:-tswg-sandbox}
export AWS_REGION=${AWS_REGION:-us-west-2}
export PATH=/usr/local/bin:/usr/bin:/bin
marker=${TSWG_EC2_MARKER:-$HOME/.cache/tslinux/ec2/last-used}
idle=${TSWG_EC2_IDLE_MINUTES:-30}
unit=tswg-ec2-idle-stop
units=$HOME/.config/systemd/user
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

case ${1:-} in
check)
	ids=$(aws ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=pending,running" \
		--query 'Reservations[].Instances[].InstanceId' --output text)
	if [ -z "$ids" ]; then
		exit 0
	fi
	if [ -f "$marker" ] && [ -n "$(find "$marker" -mmin -"$idle")" ]; then
		echo "in use (marker touched within $idle minutes): $ids"
		exit 0
	fi
	echo "idle for over $idle minutes; stopping $ids"
	# shellcheck disable=SC2086
	aws ec2 stop-instances --instance-ids $ids --output text > /dev/null
	;;
install)
	mkdir -p "$units"
	cat > "$units/$unit.service" <<EOF
[Unit]
Description=Stop idle tswg benchmark EC2 instances

[Service]
Type=oneshot
ExecStart=$self check
EOF
	cat > "$units/$unit.timer" <<EOF
[Unit]
Description=Stop idle tswg benchmark EC2 instances every 5 minutes

[Timer]
OnCalendar=*:0/5

[Install]
WantedBy=timers.target
EOF
	sudo -n loginctl enable-linger "$(id -un)"
	systemctl --user daemon-reload
	systemctl --user enable --now "$unit.timer"
	systemctl --user list-timers "$unit.timer" --no-pager
	;;
uninstall)
	systemctl --user disable --now "$unit.timer" || true
	rm -f "$units/$unit.service" "$units/$unit.timer"
	systemctl --user daemon-reload
	;;
*)
	sed -n 's/^# \{0,1\}//; /^It.s meant/,/^$/p' "$0" >&2
	exit 2
	;;
esac
