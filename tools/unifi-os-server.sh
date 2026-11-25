#!/bin/sh
# UniFi OS Server on this Linux machine, for the live tests of the unifi provider and plugin
# against UniFi OS, which no container runs: it installs the version written here, sets it up
# offline with a local admin, makes an API key, and writes the tests' variables to the file given:
#
#	tools/unifi-os-server.sh /tmp/unifi-os.env && . /tmp/unifi-os.env
#
# IPV6DDNS_LIVE_UNIFI_OS has the settings of the API key, IPV6DDNS_LIVE_UNIFI_OS_USER those of
# the admin. It needs root, or sudo, Podman 4.9.3 or later, and curl and OpenSSL; on Debian or
# Ubuntu it installs Podman and what UniFi OS Server runs it with. It takes minutes, most of them
# the UniFi Network application's start. On macOS, tools/unifi-os-vm.sh runs it in a VM.
#
# A machine it set up already is set up again: its admin's password is the one in the file.
set -eu

UOS_VERSION=5.1.42
case $(uname -m) in
x86_64 | amd64)
	url=https://fw-download.ubnt.com/data/unifi-os-server/5172-linux-x64-5.1.42-12e9e3cf-8f8b-4e54-928c-76b80a10c8a4.42-x64
	sha256=f6111e9396a42c74016f5dde9b01fbef486a6fe69efe137935e6e38b7c22f94d
	;;
aarch64 | arm64)
	url=https://fw-download.ubnt.com/data/unifi-os-server/f730-linux-arm64-5.1.42-d2bca8bd-d6fc-4d20-99e5-b78235843c2f.42-arm64
	sha256=8e29bd50cde8f781ace4b85599256ef62c02723bdc751044d4db90a087fb5207
	;;
*)
	echo "unifi-os-server: UniFi OS Server has no build for $(uname -m)" >&2
	exit 1
	;;
esac

out=${1:?usage: tools/unifi-os-server.sh <file of the variables>}
console=https://127.0.0.1:11443
sudo=
[ "$(id -u)" = 0 ] || sudo=sudo
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# wait_for <what> <seconds> <command...>: until the command succeeds.
wait_for() {
	what=$1 seconds=$2
	shift 2
	deadline=$(($(date +%s) + seconds))
	until "$@" >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "unifi-os-server: $what did not come up in ${seconds}s" >&2
			exit 1
		fi
		sleep 5
	done
}

# json <expression>: the expression of the JSON on stdin, d, as text: ['data']['id'], or .get(...).
json() {
	python3 -c "import json,sys; d=json.load(sys.stdin); print(eval('d' + sys.argv[1]))" "$1"
}

if ! command -v podman >/dev/null && command -v apt-get >/dev/null; then
	$sudo apt-get update -qq
	$sudo apt-get install -y -qq podman slirp4netns uidmap passt curl openssl >/dev/null
fi
# UniFi OS Server starts its container with pasta: Ubuntu's Podman comes without.
if command -v apt-get >/dev/null && ! command -v pasta >/dev/null; then
	$sudo apt-get install -y -qq passt >/dev/null
fi

if ! curl -fsk -o /dev/null "$console/api/system"; then
	echo "unifi-os-server: installing UniFi OS Server $UOS_VERSION" >&2
	curl -fsSL --retry 3 -o "$work/uosserver" "$url"
	echo "$sha256  $work/uosserver" | sha256sum -c - >/dev/null
	chmod +x "$work/uosserver"
	echo y | $sudo "$work/uosserver" >"$work/install.log" 2>&1 || {
		tail -30 "$work/install.log" >&2
		exit 1
	}
fi
wait_for 'UniFi OS Server' 300 curl -fsk "$console/api/system"

# Set up offline, with a local admin: no Ubiquiti account. Its password stays in the file.
password=
[ -f "$out" ] && password=$(sed -n 's/^IPV6DDNS_LIVE_UNIFI_OS_PASSWORD=//p' "$out")
if [ "$(curl -fsk "$console/api/system" | json "['isSetup']")" != True ]; then
	password=live-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
	curl -fsk -o /dev/null -H 'Content-Type: application/json' "$console/api/setup/start" -d '{"sendTrace":false,"type":"webui"}'
	curl -fsk -o /dev/null -H 'Content-Type: application/json' "$console/api/setup" \
		-d "{\"name\":\"live\",\"username\":\"admin\",\"password\":\"$password\",\"timezone\":\"UTC\",\"country\":840,\"sendDiagnostics\":false,\"location\":{\"lat\":0,\"long\":0,\"radius\":200}}"
fi
[ -n "$password" ] || {
	echo "unifi-os-server: the console is set up, and $out has no password of its admin" >&2
	exit 1
}

# An API key of the admin's: made at its login, with the CSRF token of its session.
curl -fsk -c "$work/cookies" -D "$work/headers" -o /dev/null -H 'Content-Type: application/json' \
	"$console/api/auth/login" -d "{\"username\":\"admin\",\"password\":\"$password\",\"rememberMe\":true}"
csrf=$(tr -d '\r' <"$work/headers" | sed -n 's/^[Xx]-[Cc]srf-[Tt]oken: //p')
user=$(curl -fsk -b "$work/cookies" "$console/proxy/users/api/v2/user/self" | json ".get('data', d).get('id') or d.get('data', d).get('unique_id')")
key=$(curl -fsk -b "$work/cookies" -H "X-Csrf-Token: $csrf" -H 'Content-Type: application/json' \
	"$console/proxy/users/api/v2/user/$user/keys" -d '{"name":"ipv6ddns-live"}' | json "['data']['full_api_key']")

# The UniFi Network application answers last.
wait_for 'UniFi Network' 600 curl -fsk -H "X-API-KEY: $key" "$console/proxy/network/integration/v1/sites"

fingerprint=$(openssl s_client -connect "${console#https://}" </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256 -r | cut -d' ' -f1)
version=$(curl -fsk -H "X-API-KEY: $key" "$console/proxy/network/integration/v1/info" | json "['applicationVersion']")
common="\"address\":\"$console\",\"zone\":\"example.test\",\"tls_fingerprint\":\"$fingerprint\""
# Of sh, single-quoted, as the values are JSON.
cat >"$out" <<EOF
export IPV6DDNS_LIVE_UNIFI_OS='{$common,"api_key":"$key"}'
export IPV6DDNS_LIVE_UNIFI_OS_USER='{$common,"username":"admin","password":"$password"}'
IPV6DDNS_LIVE_UNIFI_OS_PASSWORD=$password
EOF
echo "unifi-os-server: UniFi OS Server $UOS_VERSION, UniFi Network $version, at $console" >&2
