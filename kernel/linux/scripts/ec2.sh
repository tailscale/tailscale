#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# ec2.sh creates and destroys EC2 instances for benchmarking tswg on real
# cloud VMs (and bare metal) rather than nested QEMU VMs, with tailscale.com's
# lean harness in remote mode (TSWG_REMOTE, see tstest/tswgbench).
#
# Everything it creates is named bradfitz-tswg... and tagged
# owner=claude-tswg: a key pair (from ~/.ssh/bradfitz-tswg, generated if
# missing), a security group allowing SSH and the harness's agent from this
# machine's public addresses and all traffic between its members, a cluster
# placement group, and the instances, which run Ubuntu 24.04, require IMDSv2
# (the sandbox org's SCP insists), and get an IPv6 address too.
#
# "up" writes the instances' addresses to $TSWG_EC2_HOSTS (default
# ~/.cache/tslinux/ec2/hosts.json), the file TSWG_REMOTE takes.
#
# ec2-idle-stop.sh (run from a systemd user timer) stops the instances once
# nothing has touched ~/.cache/tslinux/ec2/last-used for a while; every
# command here touches it, as does the lean harness while it runs. "start"
# brings stopped instances back (with new public addresses).
#
# Environment:
#   AWS_PROFILE     default tswg-sandbox
#   AWS_REGION      default us-west-2
#   TSWG_EC2_SUBNET default subnet-c9385194 (the default VPC's IPv6 subnet in us-west-2c)
#
# usage:
#   ec2.sh up [COUNT [TYPE]]   launch COUNT (default 2) instances of TYPE (default c7i.xlarge)
#   ec2.sh start               start stopped instances, and rewrite the hosts file
#   ec2.sh stop                stop the instances (as ec2-idle-stop.sh does)
#   ec2.sh hosts               rewrite the hosts file from the running instances
#   ec2.sh ssh N [CMD...]      ssh to instance N (0-based)
#   ec2.sh down                terminate the instances and delete everything else
#   ec2.sh status              list our resources

set -eu

export AWS_PROFILE=${AWS_PROFILE:-tswg-sandbox}
export AWS_REGION=${AWS_REGION:-us-west-2}
subnet=${TSWG_EC2_SUBNET:-subnet-c9385194}
name=bradfitz-tswg
key=$HOME/.ssh/$name
hosts=${TSWG_EC2_HOSTS:-$HOME/.cache/tslinux/ec2/hosts.json}
owner='Key=owner,Value=claude-tswg'
marker=$(dirname "$hosts")/last-used

# Keep ec2-idle-stop.sh from stopping the instances while we use them.
mkdir -p "$(dirname "$marker")"
touch "$marker"

ec2() { aws ec2 "$@"; }

# tags NAME RESOURCE_TYPE prints a --tag-specifications value.
tags() { echo "ResourceType=$2,Tags=[{$owner},{Key=Name,Value=$1}]"; }

vpc_of_subnet() {
	ec2 describe-subnets --subnet-ids "$subnet" --query 'Subnets[0].VpcId' --output text
}

sg_id() {
	ec2 describe-security-groups --filters "Name=group-name,Values=$name" \
		"Name=tag:owner,Values=claude-tswg" --query 'SecurityGroups[0].GroupId' --output text
}

instance_ids() {
	ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=pending,running,stopping,stopped" \
		--query 'Reservations[].Instances[].InstanceId' --output text
}

ensure_key() {
	if [ ! -f "$key" ]; then
		ssh-keygen -q -t ed25519 -N '' -C "$name" -f "$key"
	fi
	if ! ec2 describe-key-pairs --key-names "$name" > /dev/null 2>&1; then
		ec2 import-key-pair --key-name "$name" --public-key-material "fileb://$key.pub" \
			--tag-specifications "$(tags "$name" key-pair)" > /dev/null
		echo "imported key pair $name" >&2
	fi
}

ensure_sg() {
	sg=$(sg_id)
	if [ "$sg" = "None" ] || [ -z "$sg" ]; then
		sg=$(ec2 create-security-group --group-name "$name" --vpc-id "$(vpc_of_subnet)" \
			--description "tswg benchmarks (claude-tswg)" \
			--tag-specifications "$(tags "$name" security-group)" \
			--query GroupId --output text)
		ec2 authorize-security-group-ingress --group-id "$sg" \
			--ip-permissions "IpProtocol=-1,UserIdGroupPairs=[{GroupId=$sg}]" > /dev/null
		echo "created security group $sg" >&2
	fi
	# Allow SSH and the agent from this machine, whatever its address is now.
	my4=$(curl -s -m 5 https://checkip.amazonaws.com || true)
	my6=$(curl -s -m 5 -6 https://api6.ipify.org || true)
	for port in 22 8080; do
		if [ -n "$my4" ]; then
			ec2 authorize-security-group-ingress --group-id "$sg" \
				--ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=$my4/32}]" \
				> /dev/null 2>&1 || true
		fi
		if [ -n "$my6" ]; then
			ec2 authorize-security-group-ingress --group-id "$sg" \
				--ip-permissions "IpProtocol=tcp,FromPort=$port,ToPort=$port,Ipv6Ranges=[{CidrIpv6=$my6/128}]" \
				> /dev/null 2>&1 || true
		fi
	done
	echo "$sg"
}

ensure_pg() {
	if ! ec2 describe-placement-groups --group-names "$name" > /dev/null 2>&1; then
		ec2 create-placement-group --group-name "$name" --strategy cluster \
			--tag-specifications "$(tags "$name" placement-group)" > /dev/null
		echo "created placement group $name" >&2
	fi
}

# wait_ready waits for SSH to every host in the hosts file, and for
# user-data to have installed the build tools.
wait_ready() {
	for ip in $(python3 -c 'import json,sys; print(" ".join(h["public"] for h in json.load(open(sys.argv[1]))))' "$hosts"); do
		n=0
		until ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
			-o ConnectTimeout=5 "ubuntu@$ip" test -f /var/lib/tswg-ready 2> /dev/null; do
			n=$((n + 1))
			if [ $n -gt 120 ]; then
				echo "$ip: not ready after 10 minutes" >&2
				exit 1
			fi
			sleep 5
		done
		echo "$ip: ready ($(ssh -i "$key" -o BatchMode=yes "ubuntu@$ip" uname -r))" >&2
	done
}

# The instances install what's needed to build tswg.ko against their own
# kernel, with the compiler the kernel was built with.
userdata() {
	cat <<'EOF'
#!/bin/sh
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -qy build-essential gcc-13 gcc-14 nftables "linux-headers-$(uname -r)"
touch /var/lib/tswg-ready
EOF
}

write_hosts() {
	mkdir -p "$(dirname "$hosts")"
	ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=running" \
		--query 'Reservations[].Instances[].{name:Tags[?Key==`Name`]|[0].Value,id:InstanceId,type:InstanceType,public:PublicIpAddress,private4:PrivateIpAddress,ip6:Ipv6Address}' \
		--output json | python3 -c '
import json, sys
hosts = sorted(json.load(sys.stdin), key=lambda h: h["name"])
for h in hosts:
    h["user"] = "ubuntu"
    h["key"] = sys.argv[1]
json.dump(hosts, sys.stdout, indent=2)
print()
' "$key" > "$hosts"
	echo "wrote $hosts" >&2
	cat "$hosts"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
up)
	count=${1:-2}
	type=${2:-c7i.xlarge}
	ensure_key
	sg=$(ensure_sg)
	ensure_pg
	ami=$(aws ssm get-parameter \
		--name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
		--query Parameter.Value --output text)
	stopped=$(ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=stopping,stopped" \
		--query 'length(Reservations[].Instances[])' --output text)
	if [ "$stopped" != 0 ]; then
		echo "$stopped instances are stopped; use \"$0 start\" (or \"$0 down\" first)" >&2
		exit 1
	fi
	existing=$(ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=pending,running" \
		--query 'length(Reservations[].Instances[])' --output text)
	ids=""
	i=$existing
	while [ "$i" -lt $((existing + count)) ]; do
		id=$(ec2 run-instances --image-id "$ami" --instance-type "$type" \
			--key-name "$name" --subnet-id "$subnet" --security-group-ids "$sg" \
			--placement "GroupName=$name" --ipv6-address-count 1 \
			--associate-public-ip-address \
			--metadata-options HttpTokens=required \
			--block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3,DeleteOnTermination=true}' \
			--user-data "$(userdata)" \
			--tag-specifications "$(tags "$name-$i" instance)" "$(tags "$name-$i" volume)" \
			--query 'Instances[0].InstanceId' --output text)
		echo "launched $name-$i ($type): $id" >&2
		# Let it forward packets that aren't its own, as a subnet router does.
		ec2 wait instance-exists --instance-ids "$id"
		ec2 modify-instance-attribute --instance-id "$id" --no-source-dest-check
		ids="$ids $id"
		i=$((i + 1))
	done
	# shellcheck disable=SC2086
	ec2 wait instance-running --instance-ids $ids
	write_hosts > /dev/null
	wait_ready
	cat "$hosts"
	;;
start)
	ids=$(ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		"Name=instance-state-name,Values=stopping,stopped" \
		--query 'Reservations[].Instances[].InstanceId' --output text)
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086
		ec2 wait instance-stopped --instance-ids $ids
		# shellcheck disable=SC2086
		ec2 start-instances --instance-ids $ids > /dev/null
		echo "starting $ids" >&2
		# shellcheck disable=SC2086
		ec2 wait instance-running --instance-ids $ids
	fi
	write_hosts > /dev/null
	wait_ready
	cat "$hosts"
	;;
stop)
	ids=$(instance_ids)
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086
		ec2 stop-instances --instance-ids $ids > /dev/null
		echo "stopping $ids" >&2
	fi
	;;
hosts)
	write_hosts
	;;
ssh)
	n=$1
	shift
	ip=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[int(sys.argv[2])]["public"])' "$hosts" "$n")
	exec ssh -i "$key" -o StrictHostKeyChecking=accept-new "ubuntu@$ip" "$@"
	;;
down)
	ids=$(instance_ids)
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086
		ec2 terminate-instances --instance-ids $ids > /dev/null
		echo "terminating $ids" >&2
		# shellcheck disable=SC2086
		ec2 wait instance-terminated --instance-ids $ids
	fi
	sg=$(sg_id)
	if [ "$sg" != "None" ] && [ -n "$sg" ]; then
		ec2 delete-security-group --group-id "$sg"
		echo "deleted security group $sg" >&2
	fi
	if ec2 describe-placement-groups --group-names "$name" > /dev/null 2>&1; then
		ec2 delete-placement-group --group-name "$name"
		echo "deleted placement group $name" >&2
	fi
	if ec2 describe-key-pairs --key-names "$name" > /dev/null 2>&1; then
		ec2 delete-key-pair --key-name "$name"
		echo "deleted key pair $name" >&2
	fi
	rm -f "$hosts"
	;;
status)
	ec2 describe-instances --filters "Name=tag:owner,Values=claude-tswg" \
		--query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,InstanceType,State.Name,PublicIpAddress]' \
		--output text
	echo "security group: $(sg_id)"
	ec2 describe-placement-groups --group-names "$name" --query 'PlacementGroups[0].GroupName' --output text 2> /dev/null || echo "no placement group"
	ec2 describe-key-pairs --key-names "$name" --query 'KeyPairs[0].KeyName' --output text 2> /dev/null || echo "no key pair"
	;;
*)
	sed -n 's/^# \{0,1\}//; /^usage:/,/^$/p' "$0" >&2
	exit 2
	;;
esac
