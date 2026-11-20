#!/bin/sh
# The tests as CI runs them, and the live ones, on Linux as root, from any system with Docker: in
# a container that is thrown away, privileged for its network namespaces. With Home Assistant's
# library for ESPHome devices, at CI's version, and CI's interfaces for mDNS: nothing is skipped.
# Arguments go to the live tests:
#
#	tools/live-test.sh -run '^TestLiveListenFamilies$' ./pkg/listen
#
# To test with an ipv6disc that isn't released, as when working on both, IPV6DISC names its
# directory: IPV6DISC=../ipv6disc tools/live-test.sh
set -eu
cd "$(dirname "$0")/.."
aioesphomeapi=$(grep -o 'aioesphomeapi==[0-9.]*' .github/workflows/ci.yaml)
inside='
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get install -yqq --no-install-recommends iproute2 procps python3-venv >/dev/null
	python3 -m venv /venv
	/venv/bin/pip install -q --disable-pip-version-check "$AIOESPHOMEAPI"
	if [ -n "${GOWORK:-}" ]; then
		printf "go %s\nuse (\n\t/src/ipv6ddns\n\t/src/ipv6disc\n)\n" "$(go env GOVERSION | sed s/^go//)" >"$GOWORK"
	fi
	# Docker leaves IPv6 off where its network has none: loopback has it anyway, the
	# interfaces the tests make need it.
	sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
	for n in 0 1; do
		ip link add mdns$n type dummy
		ip addr add 192.0.2.$((n + 1))/32 dev mdns$n
		ip link set mdns$n multicast on up
	done
	go vet -tags integration ./...
	go test -race -count=1 ./...
	if [ $# -eq 0 ]; then
		set -- -run "^TestLive" . ./pkg/listen ./pkg/esphome
	fi
	go test -race -count=1 -tags integration -v "$@"
'
set -- "golang:${GO_VERSION:-1.26}" sh -euc "$inside" sh "$@"
if [ -n "${IPV6DISC:-}" ]; then
	set -- -v "$(cd "$IPV6DISC" && pwd)":/src/ipv6disc:ro -e GOWORK=/go.work "$@"
fi
exec docker run --rm --privileged \
	-v "$PWD":/src/ipv6ddns:ro -v ipv6ddns-go-cache:/go/pkg/mod -v ipv6ddns-go-build:/root/.cache/go-build \
	-v ipv6ddns-pip-cache:/root/.cache/pip \
	-w /src/ipv6ddns -e GOFLAGS=-buildvcs=false -e AIOESPHOMEAPI="$aioesphomeapi" \
	-e ESPHOME_PYTHON=/venv/bin/python -e ESPHOME_COMPAT_REQUIRED=1 -e ESPHOME_MDNS_INTERFACES=mdns0,mdns1 \
	"$@"
