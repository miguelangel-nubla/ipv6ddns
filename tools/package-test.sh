#!/bin/sh
# The packages, built as a release builds them and installed where they are for, from any system
# with Docker: the deb in Debian and the rpm in Fedora, each with its systemd, and the apk in
# Alpine, with its OpenRC. Each in a container that boots its init and is thrown away. In each:
#
# - an install starts nothing;
# - the service runs with the configuration the package brings, and discovers, as the package
#   lets it, a host that is on a link with it: its addresses by NDP and by ping, its IPv4, and
#   its names, the one it announces by mDNS and the one of its DHCP requests;
# - an upgrade keeps the configuration and restarts the service;
# - a removal stops it and leaves the configuration.
#
# The build takes minutes, for every system of a release. PACKAGES_BUILT=1 tests those dist/ has.
set -eu
cd "$(dirname "$0")/.."

if [ -z "${PACKAGES_BUILT:-}" ]; then
	docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-buildvcs=false \
		-v ipv6ddns-go-cache:/go/pkg/mod -v ipv6ddns-go-build:/root/.cache/go-build \
		"goreleaser/goreleaser:${GORELEASER_VERSION:-latest}" release --snapshot --clean --skip=docker,archive
fi

# The packages of the architecture Docker runs.
arch=$(docker version --format '{{.Server.Arch}}')
package() {
	set -- dist/ipv6ddns_*_linux_"$arch.$1"
	[ $# -eq 1 ] && [ -f "$1" ] || {
		echo "package-test: not one package of $arch in dist/: $*" >&2
		exit 1
	}
	basename "$1"
}

# The service, as each init has it.
systemd='
	service_file=/usr/lib/systemd/system/ipv6ddns.service
	service_enabled() { systemctl -q is-enabled ipv6ddns.service 2>/dev/null; }
	service_active() { systemctl -q is-active ipv6ddns.service; }
	service_start() { systemctl enable -q --now ipv6ddns.service; }
	service_pid() { systemctl show -P MainPID ipv6ddns.service; }
	service_log() { journalctl -u ipv6ddns.service --no-pager; }
	# The unit has nothing systemd would warn of, and the process has its two capabilities, raw
	# sockets and the ports under 1024, and no other.
	service_limits() {
		verified=$(systemd-analyze verify --man=no "$service_file" 2>&1) || fail "the unit: $verified"
		[ -z "$verified" ] || fail "the unit: $verified"
		grep -q "^CapEff:.0000000000002400$" "/proc/$(service_pid)/status" || fail "the capabilities: $(grep ^CapEff "/proc/$(service_pid)/status")"
	}
	# Debian starts the one it installs, which would be the one of this machine, not the host'"'"'s.
	systemctl disable -q --now avahi-daemon.socket avahi-daemon.service 2>/dev/null || true
'
openrc='
	service_file=/etc/init.d/ipv6ddns
	service_enabled() { rc-update show | grep -q ipv6ddns; }
	service_active() { rc-service -q ipv6ddns status >/dev/null 2>&1; }
	service_start() { rc-update -q add ipv6ddns default && rc-service -q ipv6ddns start 2>/dev/null; }
	service_pid() { pidof ipv6ddns; }
	service_log() { grep " ipv6ddns: " /var/log/messages; }
	service_limits() { :; }
	# apk upgrades to another version only: the one installed is made an older one, in its
	# database, by its version and by its checksum, which is what apk tells packages apart by.
	older() {
		awk '"'"'
			/^C:/ { checksum = $0; next }
			/^P:/ { mine = $0 == "P:ipv6ddns"; print mine ? "C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=" : checksum }
			mine && /^V:/ { print "V:0.0.1"; next }
			{ print }
		'"'"' /lib/apk/db/installed >/tmp/installed && cat /tmp/installed >/lib/apk/db/installed
	}
'

inside='
	fail() {
		echo "package-test: $*" >&2
		service_log >&2 || true
		exit 1
	}
	config=/etc/ipv6ddns/config.yaml
	status() { curl -fsS http://127.0.0.1:8053/status.json; }
	healthy() {
		for _ in $(seq 30); do
			[ "$(curl -fsS http://127.0.0.1:8053/healthz 2>/dev/null)" = ok ] && return
			sleep 1
		done
		return 1
	}

	# An install: the files, and nothing started.
	eval "$INSTALL" >/dev/null
	ipv6ddns --version | grep -q "^ipv6ddns " || fail "the command does not say its version"
	[ "$(stat -c "%a %U" "$config")" = "600 root" ] || fail "the configuration is not of root alone: $(stat -c "%a %U" "$config")"
	zcat /usr/share/man/man1/ipv6ddns.1.gz | grep -q "^\.TH IPV6DDNS 1 " || fail "no manual page"
	! service_enabled || fail "the install enabled the service"
	! service_active || fail "the install started the service"

	# A host on a link with this machine, in a network namespace: with an address of each
	# family, which are not checked for duplicates, so that they are there at once, and an mDNS
	# responder, which says it is pkgpeer.local. Docker leaves IPv6 off where its network has none.
	echo 0 >/proc/sys/net/ipv6/conf/all/disable_ipv6
	echo 0 >/proc/sys/net/ipv6/conf/default/disable_ipv6
	ip netns add peer
	ip link add lan0 type veth peer name eth0 netns peer
	ip addr add fd00:db8::1/64 dev lan0 nodad
	ip addr add 192.0.2.1/24 dev lan0
	ip link set lan0 up
	ip -n peer addr add fd00:db8::2/64 dev eth0 nodad
	ip -n peer addr add 192.0.2.2/24 dev eth0
	ip -n peer link set lo up
	ip -n peer link set eth0 up
	mac=$(ip -n peer -o link show eth0 | sed "s/.*link\/ether \([0-9a-f:]*\).*/\1/")
	mkdir -p /run/avahi-daemon /tmp/avahi
	chown avahi:avahi /run/avahi-daemon
	printf "[server]\nhost-name=pkgpeer\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=no\nallow-interfaces=eth0\n[publish]\npublish-workstation=no\n" >/tmp/avahi/avahi-daemon.conf
	ip netns exec peer avahi-daemon -f /tmp/avahi/avahi-daemon.conf -D

	# The service, with the configuration the package brings, and IPv4, which it leaves off.
	printf "\ndiscovery:\n  ipv4:\n    enabled: true\n" >>"$config"
	service_start
	healthy || fail "the service does not answer"
	service_limits
	pid=$(service_pid)

	# It discovers the host as it would anywhere: nothing of the service is in the way of its
	# sockets. The host asks for an address by DHCP, with its name, until it is found so.
	found="
		.discovered[] | select(.mac == \$mac)
		| ([.addresses[] | select(.address == \"fd00:db8::2\") | .seen[].protocol] | index(\"ndp\") != null and index(\"ping\") != null)
			and any(.addresses[]; .address == \"192.0.2.2\")
			and any(.names[]?; .name == \"pkgpeer\" and any(.said[]; .source == \"mdns\"))
			and any(.names[]?; .name == \"pkgdhcp\" and any(.said[]; .source == \"dhcp\"))
	"
	discovered=no
	for _ in $(seq 20); do
		ip netns exec peer busybox udhcpc -i eth0 -x hostname:pkgdhcp -s /bin/true -n -q -t 1 -T 1 >/dev/null 2>&1 || true
		if status | jq -e --arg mac "$mac" "$found" >/dev/null; then
			discovered=yes
			break
		fi
		sleep 2
	done
	[ "$discovered" = yes ] || fail "the host $mac is not discovered with its two addresses, by NDP and by ping, and its two names, by mDNS and by DHCP: $(status | jq -c --arg mac "$mac" ".discovered[] | select(.mac == \$mac)")"
	! service_log | grep -Ei "not permitted|permission denied|read-only file system|\"level\":\"(error|fatal)\"" || fail "the log has errors"

	# An upgrade: the configuration stays as it was left, and the service runs the new one.
	echo "# mine" >>"$config"
	eval "$UPGRADE" >/dev/null
	grep -q "^# mine$" "$config" || fail "the upgrade replaced the configuration"
	healthy || fail "the service does not answer after the upgrade"
	[ "$(service_pid)" != "$pid" ] || fail "the upgrade did not restart the service"
	service_enabled || fail "the upgrade disabled the service"

	# A removal: stopped and gone, but for the configuration.
	eval "$REMOVE" >/dev/null
	! service_active || fail "the removal left the service running"
	! service_enabled || fail "the removal left the service enabled"
	[ ! -e "$service_file" ] && [ ! -e /usr/bin/ipv6ddns ] || fail "the removal left files"
	grep -qs "^# mine$" "$config" "$config.rpmsave" || fail "the removal took the configuration"
'

# check tests a package in a container of the image given: prepare installs what the test needs
# and ends as the init of the system, which has started once ready says so.
check() {
	image=$1 service=$2 prepare=$3 ready=$4 file=$5 install=$6 upgrade=$7 remove=$8
	name=ipv6ddns-package-test-$$
	echo "package-test: $file in $image"
	docker run -d --rm --name "$name" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
		-v "$PWD/dist":/dist:ro "$image" sh -euc "$prepare" >/dev/null
	trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
	started=no
	for _ in $(seq 180); do
		if docker exec "$name" sh -c "$ready" >/dev/null 2>&1; then
			started=yes
			break
		fi
		docker inspect "$name" >/dev/null 2>&1 || break
		sleep 1
	done
	[ "$started" = yes ] || {
		echo "package-test: the init of $image did not start" >&2
		exit 1
	}
	docker exec -e INSTALL="$install /dist/$file" -e UPGRADE="$upgrade /dist/$file" -e REMOVE="$remove" \
		"$name" sh -euc "$service$inside"
	docker rm -f "$name" >/dev/null
	trap - EXIT
}

apt='DEBIAN_FRONTEND=noninteractive apt-get install -yqq'
check debian:stable "$systemd" '
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get install -yqq --no-install-recommends systemd curl jq iproute2 avahi-daemon busybox >/dev/null
	exec /lib/systemd/systemd
' 'systemctl is-system-running | grep -Eq "running|degraded"' \
	"$(package deb)" "$apt" "$apt --reinstall" 'DEBIAN_FRONTEND=noninteractive apt-get remove -yqq ipv6ddns'

check fedora:latest "$systemd" '
	dnf install -yq systemd curl jq iproute avahi busybox >/dev/null
	exec /usr/lib/systemd/systemd
' 'systemctl is-system-running | grep -Eq "running|degraded"' \
	"$(package rpm)" 'dnf install -yq' 'dnf reinstall -yq' 'dnf remove -yq ipv6ddns'

check alpine:latest "$openrc" '
	apk add -q openrc busybox-openrc curl jq iproute2 avahi
	rc-update -q add syslog boot
	exec /sbin/init
' '[ "$(rc-status -r)" = default ]' \
	"$(package apk)" 'apk add -q --allow-untrusted' 'older && apk add -q --allow-untrusted' 'apk del -q ipv6ddns'

echo "package-test: ok"
