#!/bin/sh
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# This script detects the current operating system, and installs
# Tailscale according to that OS's conventions.

set -eu

# All the code is wrapped in a main function that gets called at the
# bottom of the file, so that a truncated partial download doesn't end
# up executing half a script.
main() {
	# Step 1: detect the current linux distro, version, and packaging system.
	#
	# We rely on a combination of 'uname' and /etc/os-release to find
	# an OS name and version, and from there work out what
	# installation method we should be using.
	#
	# The end result of this step is that the following three
	# variables are populated, if detection was successful.
	OS=""
	VERSION=""
	PACKAGETYPE=""
	APT_KEY_TYPE="" # Only for apt-based distros
	APT_SYSTEMCTL_START=false # Only needs to be true for Kali
	TRACK="${TRACK:-stable}"

	case "$TRACK" in
		stable|unstable)
			;;
		*)
			echo "unsupported track $TRACK"
			exit 1
			;;
	esac

	if [ -f /etc/os-release ]; then
		# /etc/os-release populates a number of shell variables. We care about the following:
		#  - ID: the short name of the OS (e.g. "debian", "freebsd")
		#  - VERSION_ID: the numeric release version for the OS, if any (e.g. "18.04")
		#  - VERSION_CODENAME: the codename of the OS release, if any (e.g. "buster")
		#  - UBUNTU_CODENAME: if it exists, use instead of VERSION_CODENAME
		. /etc/os-release
		case "$ID" in
			ubuntu|pop|neon|zorin|tuxedo)
				OS="ubuntu"
				if [ "${UBUNTU_CODENAME:-}" != "" ]; then
				    VERSION="$UBUNTU_CODENAME"
				else
				    VERSION="$VERSION_CODENAME"
				fi
				PACKAGETYPE="apt"
				# Third-party keyrings became the preferred method of
				# installation in Ubuntu 20.04.
				if expr "$VERSION_ID" : "2.*" >/dev/null; then
					APT_KEY_TYPE="keyring"
				else
					APT_KEY_TYPE="legacy"
				fi
				;;
			debian)
				OS="$ID"
				VERSION="$VERSION_CODENAME"
				PACKAGETYPE="apt"
				# Third-party keyrings became the preferred method of
				# installation in Debian 11 (Bullseye).
				if [ -z "${VERSION_ID:-}" ]; then
					# rolling release. If you haven't kept current, that's on you.
					APT_KEY_TYPE="keyring"
				# Parrot Security is a special case that uses ID=debian
				elif [ "$NAME" = "Parrot Security" ]; then
					# All versions new enough to have this behaviour prefer keyring
					# and their VERSION_ID is not consistent with Debian.
					APT_KEY_TYPE="keyring"
					# They don't specify the Debian version they're based off in os-release
					# but Parrot 6 is based on Debian 12 Bookworm.
					VERSION=bookworm
				elif [ "$VERSION_ID" -lt 11 ]; then
					APT_KEY_TYPE="legacy"
				else
					APT_KEY_TYPE="keyring"
				fi
				;;
			linuxmint)
				if [ "${UBUNTU_CODENAME:-}" != "" ]; then
				    OS="ubuntu"
				    VERSION="$UBUNTU_CODENAME"
				elif [ "${DEBIAN_CODENAME:-}" != "" ]; then
				    OS="debian"
				    VERSION="$DEBIAN_CODENAME"
				else
				    OS="ubuntu"
				    VERSION="$VERSION_CODENAME"
				fi
				PACKAGETYPE="apt"
				if [ "$VERSION_ID" -lt 5 ]; then
					APT_KEY_TYPE="legacy"
				else
					APT_KEY_TYPE="keyring"
				fi
				;;
			elementary)
				OS="ubuntu"
				VERSION="$UBUNTU_CODENAME"
				PACKAGETYPE="apt"
				if [ "$VERSION_ID" -lt 6 ]; then
					APT_KEY_TYPE="legacy"
				else
					APT_KEY_TYPE="keyring"
				fi
				;;
			industrial-os)
				OS="debian"
				PACKAGETYPE="apt"
				if [ "$(printf %.1s "$VERSION_ID")" -lt 5 ]; then
					VERSION="buster"
					APT_KEY_TYPE="legacy"
				else
					VERSION="bullseye"
					APT_KEY_TYPE="keyring"
				fi
				;;
			parrot|mendel)
				OS="debian"
				PACKAGETYPE="apt"
				if [ "$VERSION_ID" -lt 5 ]; then
					VERSION="buster"
					APT_KEY_TYPE="legacy"
				else
					VERSION="bullseye"
					APT_KEY_TYPE="keyring"
				fi
				;;
			galliumos)
				OS="ubuntu"
				PACKAGETYPE="apt"
				VERSION="bionic"
				APT_KEY_TYPE="legacy"
				;;
			pureos|kaisen)
				OS="debian"
				PACKAGETYPE="apt"
				VERSION="bullseye"
				APT_KEY_TYPE="keyring"
				;;
			raspbian)
				OS="$ID"
				VERSION="$VERSION_CODENAME"
				PACKAGETYPE="apt"
				# Third-party keyrings became the preferred method of
				# installation in Raspbian 11 (Bullseye).
				if [ "$VERSION_ID" -lt 11 ]; then
					APT_KEY_TYPE="legacy"
				else
					APT_KEY_TYPE="keyring"
				fi
				;;
			kali)
				OS="debian"
				PACKAGETYPE="apt"
				YEAR="$(echo "$VERSION_ID" | cut -f1 -d.)"
				APT_SYSTEMCTL_START=true
				# Third-party keyrings became the preferred method of
				# installation in Debian 11 (Bullseye), which Kali switched
				# to in roughly 2021.x releases
				if [ "$YEAR" -lt 2021 ]; then
					# Kali VERSION_ID is "kali-rolling", which isn't distinguishing
					VERSION="buster"
					APT_KEY_TYPE="legacy"
				else
					VERSION="bullseye"
					APT_KEY_TYPE="keyring"
				fi
				;;
			Deepin|deepin)  # https://github.com/tailscale/tailscale/issues/7862
				OS="debian"
				PACKAGETYPE="apt"
				if [ "$VERSION_ID" -lt 20 ]; then
					APT_KEY_TYPE="legacy"
					VERSION="buster"
				else
					APT_KEY_TYPE="keyring"
					VERSION="bullseye"
				fi
				;;
			pika)
				PACKAGETYPE="apt"
				# All versions of PikaOS are new enough to prefer keyring
				APT_KEY_TYPE="keyring"
				# Older versions of PikaOS are based on Ubuntu rather than Debian
				if [ "$VERSION_ID" -lt 4 ]; then
					OS="ubuntu"
					VERSION="$UBUNTU_CODENAME"
				else
					OS="debian"
					VERSION="$DEBIAN_CODENAME"
				fi
				;;
			sparky)
				OS="debian"
				PACKAGETYPE="apt"
				VERSION="$DEBIAN_CODENAME"
				APT_KEY_TYPE="keyring"
				;;
			centos)
				OS="$ID"
				VERSION="$VERSION_ID"
				PACKAGETYPE="dnf"
				if [ "$VERSION" = "7" ]; then
					PACKAGETYPE="yum"
				fi
				;;
			ol)
				OS="oracle"
				VERSION="$(echo "$VERSION_ID" | cut -f1 -d.)"
				PACKAGETYPE="dnf"
				if [ "$VERSION" = "7" ]; then
					PACKAGETYPE="yum"
				fi
				;;
			rhel|miraclelinux)
				OS="$ID"
				if [ "$ID" = "miraclelinux" ]; then
					OS="rhel"
				fi
				VERSION="$(echo "$VERSION_ID" | cut -f1 -d.)"
				PACKAGETYPE="dnf"
				if [ "$VERSION" = "7" ]; then
					PACKAGETYPE="yum"
				fi
				;;
			fedora)
				OS="$ID"
				VERSION=""
				PACKAGETYPE="dnf"
				;;
			rocky|almalinux|nobara|openmandriva|sangoma|risios|cloudlinux|alinux|fedora-asahi-remix)
				OS="fedora"
				VERSION=""
				PACKAGETYPE="dnf"
				;;
			amzn)
				OS="amazon-linux"
				VERSION="$VERSION_ID"
				PACKAGETYPE="yum"
				;;
			xenenterprise)
				OS="centos"
				VERSION="$(echo "$VERSION_ID" | cut -f1 -d.)"
				PACKAGETYPE="yum"
				;;
			opensuse-leap|sles)
				OS="opensuse"
				VERSION="leap/$VERSION_ID"
				PACKAGETYPE="zypper"
				;;
			opensuse-tumbleweed)
				OS="opensuse"
				VERSION="tumbleweed"
				PACKAGETYPE="zypper"
				;;
			sle-micro-rancher)
				OS="opensuse"
				VERSION="leap/15.4"
				PACKAGETYPE="zypper"
				;;
			arch|archarm|endeavouros|blendos|garuda|archcraft|cachyos)
				OS="arch"
				VERSION="" # rolling release
				PACKAGETYPE="pacman"
				;;
			manjaro|manjaro-arm|biglinux)
				OS="manjaro"
				VERSION="" # rolling release
				PACKAGETYPE="pacman"
				;;
			alpine)
				OS="$ID"
				VERSION="$VERSION_ID"
				PACKAGETYPE="apk"
				;;
			postmarketos)
				OS="alpine"
				VERSION="$VERSION_ID"
				PACKAGETYPE="apk"
				;;
			nixos)
				echo "Please add Tailscale to your NixOS configuration directly:"
				echo
				echo "services.tailscale.enable = true;"
				exit 1
				;;
			bazzite)
				echo "Bazzite comes with Tailscale installed by default."
				echo "Please enable Tailscale by running the following commands as root:"
				echo
				echo "ujust enable-tailscale"
				echo "tailscale up"
				exit 1
				;;
			void)
				OS="$ID"
				VERSION="" # rolling release
				PACKAGETYPE="xbps"
				;;
			gentoo)
				OS="$ID"
				VERSION="" # rolling release
				PACKAGETYPE="emerge"
				;;
			freebsd)
				OS="$ID"
				VERSION="$(echo "$VERSION_ID" | cut -f1 -d.)"
				PACKAGETYPE="pkg"
				;;
			osmc)
				OS="debian"
				PACKAGETYPE="apt"
				VERSION="bullseye"
				APT_KEY_TYPE="keyring"
				;;
			photon)
				OS="photon"
				VERSION="$(echo "$VERSION_ID" | cut -f1 -d.)"
				PACKAGETYPE="tdnf"
				;;

			# TODO: wsl?
			# TODO: synology? qnap?
		esac
	fi

	# If we failed to detect something through os-release, consult
	# uname and try to infer things from that.
	if [ -z "$OS" ]; then
		if type uname >/dev/null 2>&1; then
			case "$(uname)" in
				FreeBSD)
					# FreeBSD before 12.2 doesn't have
					# /etc/os-release, so we wouldn't have found it in
					# the os-release probing above.
					OS="freebsd"
					VERSION="$(freebsd-version | cut -f1 -d.)"
					PACKAGETYPE="pkg"
					;;
				OpenBSD)
					OS="openbsd"
					VERSION="$(uname -r)"
					PACKAGETYPE=""
					;;
				Darwin)
					OS="macos"
					VERSION="$(sw_vers -productVersion | cut -f1-2 -d.)"
					PACKAGETYPE="appstore"
					;;
				Linux)
					OS="other-linux"
					VERSION=""
					PACKAGETYPE=""
					;;
			esac
		fi
	fi

	# Ideally we want to use curl, but on some installs we
	# only have wget. Detect and use what's available.
	CURL=
	if type curl >/dev/null; then
		CURL="curl -fsSL"
	elif type wget >/dev/null; then
		CURL="wget -q -O-"
	fi
	if [ -z "$CURL" ]; then
		echo "The installer needs either curl or wget to download files."
		echo "Please install either curl or wget to proceed."
		exit 1
	fi

	TEST_URL="https://pkgs.tailscale.com/"
	RC=0
	TEST_OUT=$($CURL "$TEST_URL" 2>&1) || RC=$?
	if [ $RC != 0 ]; then
		echo "The installer cannot reach $TEST_URL"
		echo "Please make sure that your machine has internet access."
		echo "Test output:"
		echo $TEST_OUT
		exit 1
	fi

	# Step 2: having detected an OS we support, is it one of the
	# versions we support?
	OS_UNSUPPORTED=
	case "$OS" in
		ubuntu|debian|raspbian|centos|oracle|rhel|amazon-linux|opensuse|photon)
			# Check with the package server whether a given version is supported.
			URL="https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/installer-supported"
			$CURL "$URL" 2> /dev/null | grep -q OK || OS_UNSUPPORTED=1
			;;
		fedora)
			# All versions supported, no version checking required.
			;;
		arch)
			# Rolling release, no version checking needed.
			;;
		manjaro)
			# Rolling release, no version checking needed.
			;;
		alpine)
			# All versions supported, no version checking needed.
			# TODO: is that true? When was tailscale packaged?
			;;
		void)
			# Rolling release, no version checking needed.
			;;
		gentoo)
			# Rolling release, no version checking needed.
			;;
		freebsd)
			if [ "$VERSION" != "12" ] && \
			   [ "$VERSION" != "13" ] && \
			   [ "$VERSION" != "14" ] && \
			   [ "$VERSION" != "15" ]
			then
				OS_UNSUPPORTED=1
			fi
			;;
		openbsd)
			OS_UNSUPPORTED=1
			;;
		macos)
			# We delegate macOS installation to the app store, it will
			# perform version checks for us.
			;;
		other-linux)
			OS_UNSUPPORTED=1
			;;
		*)
			OS_UNSUPPORTED=1
			;;
	esac
	if [ "$OS_UNSUPPORTED" = "1" ]; then
		case "$OS" in
			other-linux)
				echo "Couldn't determine what kind of Linux is running."
				echo "You could try the static binaries at:"
				echo "https://pkgs.tailscale.com/$TRACK/#static"
				;;
			"")
				echo "Couldn't determine what operating system you're running."
				;;
			*)
				echo "$OS $VERSION isn't supported by this script yet."
				;;
		esac
		echo
		echo "If you'd like us to support your system better, please email support@tailscale.com"
		echo "and tell us what OS you're running."
		echo
		echo "Please include the following information we gathered from your system:"
		echo
		echo "OS=$OS"
		echo "VERSION=$VERSION"
		echo "PACKAGETYPE=$PACKAGETYPE"
		if type uname >/dev/null 2>&1; then
			echo "UNAME=$(uname -a)"
		else
			echo "UNAME="
		fi
		echo
		if [ -f /etc/os-release ]; then
			cat /etc/os-release
		else
			echo "No /etc/os-release"
		fi
		exit 1
	fi

	# Step 3: work out if we can run privileged commands, and if so,
	# how.
	CAN_ROOT=
	SUDO=
	if [ "$(id -u)" = 0 ]; then
		CAN_ROOT=1
		SUDO=""
	elif type sudo >/dev/null; then
		CAN_ROOT=1
		SUDO="sudo"
	elif type doas >/dev/null; then
		CAN_ROOT=1
		SUDO="doas"
	fi
	if [ "$CAN_ROOT" != "1" ]; then
		echo "This installer needs to run commands as root."
		echo "We tried looking for 'sudo' and 'doas', but couldn't find them."
		echo "Either re-run this script as root, or set up sudo/doas."
		exit 1
	fi


	# Step 4: run the installation.
	OSVERSION="$OS"
	[ "$VERSION" != "" ] && OSVERSION="$OSVERSION $VERSION"
	echo "Installing Tailscale for $OSVERSION, using method $PACKAGETYPE"
	case "$PACKAGETYPE" in
		apt)
			export DEBIAN_FRONTEND=noninteractive
			if [ "$APT_KEY_TYPE" = "legacy" ] && ! type gpg >/dev/null; then
				$SUDO apt-get update
				$SUDO apt-get install -y gnupg
			fi

			set -x
			$SUDO mkdir -p --mode=0755 /usr/share/keyrings
			case "$APT_KEY_TYPE" in
				legacy)
					$CURL "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION.asc" | $SUDO apt-key add -
					$CURL "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION.list" | $SUDO tee /etc/apt/sources.list.d/tailscale.list
					$SUDO chmod 0644 /etc/apt/sources.list.d/tailscale.list
				;;
				keyring)
					$CURL "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION.noarmor.gpg" | $SUDO tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
					$SUDO chmod 0644 /usr/share/keyrings/tailscale-archive-keyring.gpg
					$CURL "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION.tailscale-keyring.list" | $SUDO tee /etc/apt/sources.list.d/tailscale.list
					$SUDO chmod 0644 /etc/apt/sources.list.d/tailscale.list
				;;
			esac
			$SUDO apt-get update
			$SUDO apt-get install -y tailscale tailscale-archive-keyring
			if [ "$APT_SYSTEMCTL_START" = "true" ]; then
				$SUDO systemctl enable --now tailscaled
				$SUDO systemctl start tailscaled
			fi
			set +x
		;;
		yum)
			set -x
			$SUDO yum install yum-utils -y
			$SUDO yum-config-manager -y --add-repo "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo"
			$SUDO yum install tailscale -y
			$SUDO systemctl enable --now tailscaled
			set +x
		;;
		dnf)
			# DNF 5 has a different argument format; determine which one we have.
			DNF_VERSION="3"
			if LANG=C.UTF-8 dnf --version | grep -q '^dnf5 version'; then
				DNF_VERSION="5"
			fi

			# The 'config-manager' plugin wasn't implemented when
			# DNF5 was released; detect that and use the old
			# version if necessary.
			if [ "$DNF_VERSION" = "5" ]; then
				set -x
				$SUDO dnf install -y 'dnf-command(config-manager)' && DNF_HAVE_CONFIG_MANAGER=1 || DNF_HAVE_CONFIG_MANAGER=0
				set +x

				if [ "$DNF_HAVE_CONFIG_MANAGER" != "1" ]; then
					if type dnf-3 >/dev/null; then
						DNF_VERSION="3"
					else
						echo "dnf 5 detected, but 'dnf-command(config-manager)' not available and dnf-3 not found"
						exit 1
					fi
				fi
			fi

			set -x
			if [ "$DNF_VERSION" = "3" ]; then
				$SUDO dnf install -y 'dnf-command(config-manager)'
				$SUDO dnf config-manager --add-repo "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo"
			elif [ "$DNF_VERSION" = "5" ]; then
				# Already installed config-manager, above.
				$SUDO dnf config-manager addrepo --from-repofile="https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo"
			else
				echo "unexpected: unknown dnf version $DNF_VERSION"
				exit 1
			fi
			$SUDO dnf install -y tailscale
			$SUDO systemctl enable --now tailscaled
			set +x
		;;
		tdnf)
			set -x
			curl -fsSL "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo" > /etc/yum.repos.d/tailscale.repo
			$SUDO tdnf install -y tailscale
			$SUDO systemctl enable --now tailscaled
			set +x
		;;
		zypper)
			set -x
			$SUDO rpm --import "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/repo.gpg"
			$SUDO zypper --non-interactive ar -g -r "https://pkgs.tailscale.com/$TRACK/$OS/$VERSION/tailscale.repo"
			$SUDO zypper --non-interactive --gpg-auto-import-keys refresh
			$SUDO zypper --non-interactive install tailscale
			$SUDO systemctl enable --now tailscaled
			set +x
			;;
		pacman)
			set -x
			$SUDO pacman -S tailscale --noconfirm
			$SUDO systemctl enable --now tailscaled
			set +x
			;;
		pkg)
			set -x
			$SUDO pkg install --yes tailscale
			$SUDO service tailscaled enable
			$SUDO service tailscaled start
			set +x
			;;
		apk)
			set -x
			if ! grep -Eq '^http.*/community$' /etc/apk/repositories; then
				if type setup-apkrepos >/dev/null; then
					$SUDO setup-apkrepos -c -1
				else
					echo "installing tailscale requires the community repo to be enabled in /etc/apk/repositories"
					exit 1
				fi
			fi
			$SUDO apk add tailscale
			$SUDO rc-update add tailscale
			$SUDO rc-service tailscale start
			set +x
			;;
		xbps)
			set -x
			$SUDO xbps-install tailscale -y
			set +x
			;;
		emerge)
			set -x
			$SUDO emerge --ask=n net-vpn/tailscale
			set +x
			;;
		appstore)
			set -x
			open "https://apps.apple.com/us/app/tailscale/id1475387142"
			set +x
			;;
		*)
			echo "unexpected: unknown package type $PACKAGETYPE"
			exit 1
			;;
	esac

	echo "Installation complete! Log in to start using Tailscale by running:"
	echo
	if [ -z "$SUDO" ]; then
		echo "tailscale up"
	else
		echo "$SUDO tailscale up"
	fi
}

main
