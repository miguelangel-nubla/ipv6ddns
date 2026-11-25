#!/bin/sh
# The live tests of the DNS providers, ddns/live_test.go, against the real servers that run in a
# container: Technitium DNS Server, Gravity, AdGuard Home, Pi-hole, BIND, OpenWrt, a self-hosted
# UniFi Network Application with its MongoDB, and Mikrotik RouterOS, a CHR under QEMU. It
# starts them, provisions each with a zone, a credential and the records the tests must leave
# alone, runs the tests and removes them. It needs Docker, Go, curl, OpenSSL and OpenSSH's
# ssh-keygen and ssh-keyscan. The RouterOS image stays, in the Docker volume ipv6ddns-live-routeros: it is
# downloaded once.
#
# Arguments go to go test: tools/live-providers.sh -run '^TestLiveGravity$'
#
# The tests of the providers that are a service, Cloudflare, deSEC, DuckDNS and Route 53, run too when
# their variables are set: see ddns/live_cloud_test.go.
#
# The servers are of the versions written here, so that a run tells of the code and not of what
# was released that day: a newer one is a change of this file, which CI then runs.
set -eu
cd "$(dirname "$0")/.."

TECHNITIUM_IMAGE=${TECHNITIUM_IMAGE:-technitium/dns-server:15.6.2}
GRAVITY_IMAGE=${GRAVITY_IMAGE:-ghcr.io/beryju/gravity:v0.34.0}
ADGUARDHOME_IMAGE=${ADGUARDHOME_IMAGE:-adguard/adguardhome:v1.0.0}
PIHOLE_IMAGE=${PIHOLE_IMAGE:-pihole/pihole:2026.11.0}
# ISC's image is of amd64 alone: BIND 9.20.31.
# Let's Encrypt's test authority, of ACME, 2.7.0.
PEBBLE_IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble@sha256:c156cabea562e43ed0060bddc03539c07de40e311b52c6b0e5ea710a496e56b8}
BIND_IMAGE=${BIND_IMAGE:-internetsystemsconsortium/bind9:9.20@sha256:978201d91548ec63c3b1c1befd5e6a3c9fa127f79f9058fd82d8e3493fe90ce1}
# The UniFi Network Application 10.6.109, self-hosted, and the MongoDB it keeps its settings in.
# The ACME clients that get certificates through the resolver's dynamic updates.
CERTBOT_IMAGE=${CERTBOT_IMAGE:-certbot/dns-rfc2136:v5.10.0@sha256:bc280757312c9b26cc614475977aa0445b0bf6bd7119d68c4f464cbaa9de9959}
LEGO_IMAGE=${LEGO_IMAGE:-goacme/lego:v5.7.0@sha256:9fe6151508c0e1ddc51a6d3e474353520f4b008782bf0c6d31676da72e6d4766}
ACMESH_IMAGE=${ACMESH_IMAGE:-neilpang/acme.sh:3.1.7@sha256:78d9f4ec812fd1ca48d565fac9fee78ca67f607175afc3c58f62784b4100a369}
# Kea's DHCP-DDNS, which sends a DHCP server's names to the resolver's dynamic updates.
KEA_IMAGE=${KEA_IMAGE:-docker.cloudsmith.io/isc/docker/kea-dhcp-ddns:3.0.2@sha256:0047489b20627867996d5bda36e3ab58624c0b78eb4f6aed16de7beaccf9bbc1}
UNIFI_IMAGE=${UNIFI_IMAGE:-lscr.io/linuxserver/unifi-network-application:10.6.109-ls155}
MONGO_IMAGE=${MONGO_IMAGE:-mongo@sha256:41e8195b2791692695e1dc9bd21cd51d0a3af05fff8ace9304a5c1acf94f1ae1}
OPENWRT_VERSION=${OPENWRT_VERSION:-25.12.6}
case $(docker version --format '{{.Server.Arch}}') in
arm64 | aarch64) openwrt_target=armsr-armv8 openwrt_platform=linux/aarch64_generic ;;
*) openwrt_target=x86-64 openwrt_platform=linux/amd64 ;;
esac
OPENWRT_IMAGE=${OPENWRT_IMAGE:-openwrt/rootfs:$openwrt_target-$OPENWRT_VERSION}
ROUTEROS_VERSION=${ROUTEROS_VERSION:-7.20.4}

zone=example.test
password=live-$$
prefix=ipv6ddns-live-$$
work=$(mktemp -d)
cleanup() {
	docker rm -f "$prefix-technitium" "$prefix-gravity" "$prefix-adguardhome" "$prefix-pihole" "$prefix-bind" "$prefix-pebble" "$prefix-openwrt" "$prefix-routeros" "$prefix-unifi" "$prefix-unifi-mongo" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# port <container> <port/protocol>: where the host has it.
port() {
	docker port "$prefix-$1" "$2" | sed -n '1s/.*://p'
}

# wait_for <what> <command...>: until the command succeeds, a minute at most, or the $wait_seconds
# given. What became of the containers tells why it didn't.
wait_for() {
	what=$1
	shift
	deadline=$(($(date +%s) + ${wait_seconds:-60}))
	until "$@" >/dev/null 2>&1; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			echo "live-providers: $what did not come up" >&2
			docker ps -a --filter "name=$prefix-" --format '{{.Names}}: {{.Status}}' >&2
			exit 1
		fi
		sleep 0.5
	done
}

# json_field <name>: the value of a string field of the JSON object on the input.
json_field() {
	sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p'
}

publish='-p 127.0.0.1::53/udp -p 127.0.0.1::53/tcp'

# They all start at once, and are provisioned as each comes up. RouterOS first, the one that takes
# longest: it is an x86 machine, emulated unless the container has KVM, which boots in half a
# minute even so.
kvm=
if [ -w /dev/kvm ]; then
	kvm='--device /dev/kvm'
fi
# QEMU of Alpine 3.22, 10.0: the 11.0 of later ones forwards no UDP to the machine, so its DNS,
# port 53, never answers.
docker run -d --name "$prefix-routeros" $kvm $publish -p 127.0.0.1::80/tcp -p 127.0.0.1::8728/tcp -p 127.0.0.1::8729/tcp \
	-v ipv6ddns-live-routeros:/cache -e VERSION="$ROUTEROS_VERSION" alpine:3.22 sh -euc '
		apk add -q qemu-system-x86_64
		if [ ! -f "/cache/chr-$VERSION.img" ]; then
			wget -q -O /tmp/chr.zip "https://download.mikrotik.com/routeros/$VERSION/chr-$VERSION.img.zip"
			unzip -q -o /tmp/chr.zip -d /tmp
			mv "/tmp/chr-$VERSION.img" /cache/
		fi
		cp "/cache/chr-$VERSION.img" /tmp/chr.img
		accel=tcg
		if [ -w /dev/kvm ]; then
			accel=kvm
		fi
		forward=hostfwd=tcp::80-:80,hostfwd=tcp::8728-:8728,hostfwd=tcp::8729-:8729,hostfwd=tcp::53-:53,hostfwd=udp::53-:53
		exec qemu-system-x86_64 -accel "$accel" -m 256 -nographic -drive file=/tmp/chr.img,format=raw,if=virtio \
			-device virtio-net-pci,netdev=net -netdev "user,id=net,$forward"' >/dev/null
docker run -d --name "$prefix-technitium" $publish -p 127.0.0.1::5380/tcp \
	-e DNS_SERVER_ADMIN_PASSWORD="$password" "$TECHNITIUM_IMAGE" >/dev/null
docker run -d --name "$prefix-gravity" $publish -p 127.0.0.1::8008/tcp \
	-e ADMIN_PASSWORD="$password" -e ADMIN_TOKEN="$password" "$GRAVITY_IMAGE" >/dev/null
# AdGuard Home starts with its setup, on port 3000, and has its web interface on 80 once set up.
docker run -d --name "$prefix-adguardhome" $publish -p 127.0.0.1::3000/tcp -p 127.0.0.1::80/tcp "$ADGUARDHOME_IMAGE" >/dev/null
# Pi-hole answers the host, which is not of its network, and has the TXT records as lines of
# dnsmasq's: what the environment sets, the API can't change, so the other record is added later.
docker run -d --name "$prefix-pihole" $publish -p 127.0.0.1::80/tcp \
	-e FTLCONF_webserver_api_password="$password" -e FTLCONF_dns_listeningMode=all \
	-e FTLCONF_misc_dnsmasq_lines="txt-record=live.$zone,keep;txt-record=$zone,keep" "$PIHOLE_IMAGE" >/dev/null

# The UniFi Network Application, in the network of its MongoDB, which has the port: a user of
# each of its databases, made at MongoDB's first start.
cat >"$work/unifi-mongo.js" <<EOF
for (const name of ["unifi", "unifi_stat", "unifi_audit"]) {
	db.getSiblingDB(name).createUser({user: "unifi", pwd: "$password", roles: [{role: "dbOwner", db: name}]});
}
EOF
docker run -d --name "$prefix-unifi-mongo" -p 127.0.0.1::8443/tcp \
	-v "$work/unifi-mongo.js:/docker-entrypoint-initdb.d/unifi.js:ro" "$MONGO_IMAGE" >/dev/null
# UniFi joins MongoDB's network, which is gone if MongoDB ended: its log says why, as a CPU
# without the AVX that MongoDB needs.
sleep 2
if [ "$(docker inspect -f '{{.State.Running}}' "$prefix-unifi-mongo")" != true ]; then
	echo "live-providers: MongoDB, of UniFi, ended:" >&2
	docker logs --tail 40 "$prefix-unifi-mongo" 2>&1 | sed 's/^/  mongo: /' >&2
	grep -o -m1 -w avx /proc/cpuinfo >/dev/null 2>&1 || echo "live-providers: this CPU has no AVX" >&2
	exit 1
fi
docker run -d --name "$prefix-unifi" --network "container:$prefix-unifi-mongo" \
	-e MONGO_USER=unifi -e MONGO_PASS="$password" -e MONGO_HOST=127.0.0.1 -e MONGO_PORT=27017 \
	-e MONGO_DBNAME=unifi -e MONGO_AUTHSOURCE=unifi "$UNIFI_IMAGE" >/dev/null

# BIND: the primary of the zone, which takes the updates a TSIG key signs, with the records the
# tests must leave alone. Its zone file is copied where BIND can write its journal.
bind_secret=$(head -c 32 /dev/urandom | base64)
mkdir -p "$work/bind"
cat >"$work/bind/named.conf" <<EOF
options {
	directory "/var/cache/bind";
	listen-on { any; };
	listen-on-v6 { none; };
	recursion no;
	allow-query { any; };
	dnssec-validation no;
};
key "live-key." {
	algorithm hmac-sha256;
	secret "$bind_secret";
};
zone "$zone" {
	type primary;
	file "/var/lib/bind/$zone.zone";
	update-policy { grant live-key. zonesub ANY; };
};
EOF
cat >"$work/bind/$zone.zone" <<EOF
\$TTL 300
@	IN SOA ns.$zone. hostmaster.$zone. 1 3600 600 86400 60
@	IN NS ns.$zone.
@	IN TXT "keep"
ns	IN A 127.0.0.1
other	IN AAAA 2001:db8::f
live	IN TXT "keep"
EOF
chmod -R a+rX "$work/bind"
# BIND's network is Pebble's too, which checks the challenges at BIND, 127.0.0.1:53: its ports,
# of ACME and of its management, are published with BIND's.
docker run -d --name "$prefix-bind" --platform linux/amd64 $publish -p 127.0.0.1::14000/tcp -p 127.0.0.1::15000/tcp -v "$work/bind:/etc/bind/live:ro" --entrypoint sh "$BIND_IMAGE" -c "
	cp /etc/bind/live/$zone.zone /var/lib/bind/ && chown bind:bind /var/lib/bind/$zone.zone
	exec named -u bind -g -c /etc/bind/live/named.conf" >/dev/null

# OpenWrt boots as on a router, with procd, which a reload of dnsmasq goes through: its lan is the
# container's interface, with the address Docker gave it, and the firewall, which has no zone for
# the host, stays off. The TXT record is dnsmasq's own, and the host section a static lease of the
# name: neither is a domain section.
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
docker run -d --name "$prefix-openwrt" --platform "$openwrt_platform" --privileged $publish -p 127.0.0.1::22/tcp \
	-e PUBKEY="$(cat "$work/key.pub")" "$OPENWRT_IMAGE" sh -c '
		rm -f /etc/rc.d/S*firewall /etc/rc.d/S*odhcpd /etc/rc.d/S*sysntpd /etc/rc.d/S*uhttpd
		address=$(ip -4 -o addr show eth0 | awk "{print \$4}")
		gateway=$(ip -4 route show default | awk "{print \$3}")
		cat >/etc/config/network <<EOF
config interface loopback
	option device lo
	option proto static
	list ipaddr 127.0.0.1/8

config interface lan
	option device eth0
	option proto static
	list ipaddr $address
	option gateway $gateway
EOF
		cat >>/etc/config/dhcp <<EOF

config domain fixture_other
	option name other.lan
	option ip 2001:db8::f

config host fixture_host
	option name live.lan
	option ip 192.0.2.99
	option mac 02:00:00:00:00:99
EOF
		echo "txt-record=live.lan,keep" >>/etc/dnsmasq.conf
		mkdir -p /etc/dropbear
		echo "$PUBKEY" >/etc/dropbear/authorized_keys
		chmod 600 /etc/dropbear/authorized_keys
		exec /sbin/init' >/dev/null

# AdGuard Home: a user, and the rewrite the tests must leave alone. A name with a rewrite answers
# nothing of another type, so there is no TXT record to keep beside one. A name without one is
# asked upstream, which the test has none for: a rule answers that the zone's names don't exist,
# and a rewrite comes before it.
adguardhome_setup=http://127.0.0.1:$(port adguardhome 3000/tcp)
adguardhome=http://127.0.0.1:$(port adguardhome 80/tcp)
wait_for 'AdGuard Home' curl -fs "$adguardhome_setup/control/install/get_addresses"
curl -fs -H 'Content-Type: application/json' "$adguardhome_setup/control/install/configure" \
	-d "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":80},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":53},\"username\":\"admin\",\"password\":\"$password\"}" >/dev/null
wait_for 'AdGuard Home, set up' curl -fs -u "admin:$password" "$adguardhome/control/rewrite/list"
curl -fs -u "admin:$password" -H 'Content-Type: application/json' "$adguardhome/control/rewrite/add" \
	-d "{\"domain\":\"other.$zone\",\"answer\":\"2001:db8::f\"}" >/dev/null
curl -fs -u "admin:$password" -H 'Content-Type: application/json' "$adguardhome/control/filtering/set_rules" \
	-d "{\"rules\":[\"||$zone^\$dnsrewrite=NXDOMAIN;;\"]}" >/dev/null

# Pi-hole: the record the tests must leave alone, with a session of its own.
pihole=http://127.0.0.1:$(port pihole 80/tcp)
wait_seconds=120 wait_for Pi-hole curl -fs -H 'Content-Type: application/json' "$pihole/api/auth" -d "{\"password\":\"$password\"}"
pihole_sid=$(curl -fs -H 'Content-Type: application/json' "$pihole/api/auth" -d "{\"password\":\"$password\"}" | json_field sid)
curl -fs -X PUT -H "X-FTL-SID: $pihole_sid" "$pihole/api/config/dns/hosts/2001:db8::f%20other.$zone" >/dev/null
curl -fs -X DELETE -H "X-FTL-SID: $pihole_sid" "$pihole/api/auth" >/dev/null

# The UniFi Network Application: its first start, set up as its wizard would, with an admin.
# It takes minutes to come up. Its certificate is its own: the test pins it.
unifi=https://127.0.0.1:$(port unifi-mongo 8443/tcp)
wait_seconds=600 wait_for 'UniFi Network' sh -c "curl -fsk '$unifi/status' | grep -q '\"up\":true'"
curl -fsk -H 'Content-Type: application/json' "$unifi/api/cmd/sitemgr" \
	-d "{\"cmd\":\"add-default-admin\",\"name\":\"admin\",\"email\":\"admin@example.test\",\"x_password\":\"$password\"}" >/dev/null
curl -fsk -H 'Content-Type: application/json' "$unifi/api/cmd/system" -d '{"cmd":"set-installed"}' >/dev/null
unifi_fingerprint=$(openssl s_client -connect "${unifi#https://}" </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256 -r | cut -d' ' -f1)

wait_for BIND docker exec "$prefix-bind" dig +short +tcp @127.0.0.1 "$zone" SOA
docker run -d --name "$prefix-pebble" --network "container:$prefix-bind" -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
	"$PEBBLE_IMAGE" -config test/config/pebble-config.json -dnsserver 127.0.0.1:53 >/dev/null
docker cp -q "$prefix-pebble:/test/certs/pebble.minica.pem" "$work/pebble-ca.pem"
pebble=https://127.0.0.1:$(port bind 14000/tcp)
# The ACME clients join BIND's network, where Pebble is, and reach the resolver of the tests on
# this machine: Docker Desktop's host, or the gateway of the network, on Linux.
acme_host=$(docker exec "$prefix-bind" getent ahostsv4 host.docker.internal 2>/dev/null | awk '{ print $1; exit }')
[ -n "$acme_host" ] || acme_host=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$prefix-bind")
wait_for Pebble curl -fs --cacert "$work/pebble-ca.pem" "$pebble/dir"

# Technitium: an API token, a primary zone and the records.
technitium=http://127.0.0.1:$(port technitium 5380/tcp)
wait_for Technitium curl -fs "$technitium/api/user/login?user=admin&pass=$password"
technitium_token=$(curl -fs "$technitium/api/user/createToken?user=admin&pass=$password&tokenName=live" | json_field token)
technitium_api() {
	path=$1
	shift
	curl -fs "$technitium/api/zones/$path?token=$technitium_token&zone=$zone" "$@" | grep -q '"status":"ok"' || {
		echo "live-providers: Technitium refused $path $*" >&2
		exit 1
	}
}
technitium_api create --data-urlencode type=Primary -G
technitium_api records/add -G -d "domain=other.$zone" -d type=AAAA -d ipAddress=2001:db8::f -d ttl=300
technitium_api records/add -G -d "domain=live.$zone" -d type=TXT -d text=keep -d ttl=300
technitium_api records/add -G -d "domain=$zone" -d type=TXT -d text=keep -d ttl=300

# Gravity: the token is the one it starts with. An authoritative zone, and the records. The zone
# answers from etcd, without the memory handler in front of it that the zones made in the web
# interface have: Gravity 0.34.0 answers through that one with a single record of each type,
# whatever the number the name has.
gravity=http://127.0.0.1:$(port gravity 8008/tcp)
gravity_api() {
	path=$1
	shift
	curl -fs -o /dev/null -H "Authorization: Bearer $password" -H 'Content-Type: application/json' "$gravity/api/v1/dns/$path" "$@"
}
wait_for Gravity gravity_api zones
gravity_api "zones?zone=$zone." -d '{"authoritative":true,"handlerConfigs":[{"type":"etcd"}],"defaultTTL":86400,"hook":""}'
gravity_api "zones/records?zone=$zone.&hostname=other&uid=fixture" -d '{"type":"AAAA","data":"2001:db8::f","ttl":300}'
gravity_api "zones/records?zone=$zone.&hostname=live&uid=fixture" -d '{"type":"TXT","data":"keep","ttl":300}'
gravity_api "zones/records?zone=$zone.&hostname=@&uid=fixture" -d '{"type":"TXT","data":"keep","ttl":300}'

# OpenWrt: up once dnsmasq serves, and dropbear has made its host keys, an Ed25519 one and an RSA
# one, whose fingerprints these are. They are of the one scan that showed both, asked for those two
# kinds alone: ssh-keyscan writes its comments where it writes the keys, and a scan for every kind
# there is comes back from dropbear without one of the two, one time in four.
openwrt_ssh=$(port openwrt 22/tcp)
openwrt_scan() {
	ssh-keyscan -t rsa,ed25519 -p "$openwrt_ssh" 127.0.0.1 2>/dev/null | grep -v '^#' >"$work/host_keys"
	[ "$(grep -c . "$work/host_keys")" -eq 2 ]
}
wait_for OpenWrt docker exec "$prefix-openwrt" nslookup other.lan 127.0.0.1
wait_for "OpenWrt's SSH" openwrt_scan
openwrt_host_keys=$(ssh-keygen -lf "$work/host_keys" | awk '{print $2}' | tr '\n' ' ')

# RouterOS: as it boots the first time, with the user admin and no password. Over its REST API,
# the DNS server answers the host, the records, and a certificate of its own for the API over TLS.
routeros=http://127.0.0.1:$(port routeros 80/tcp)
routeros_api() {
	path=$1
	shift
	curl -fs -m 60 -u admin: -H 'Content-Type: application/json' "$routeros/rest/$path" "$@"
}
# Five minutes: the first time it is downloaded, and without KVM it is emulated.
routeros_up() {
	curl -fs -m 5 -u admin: "$routeros/rest/system/resource"
}
wait_seconds=300 wait_for RouterOS routeros_up
routeros_api ip/dns/set -d '{"allow-remote-requests":"yes"}' >/dev/null
routeros_api ip/dns/static/add -d '{"name":"other.lan","type":"AAAA","address":"2001:db8::f"}' >/dev/null
routeros_api ip/dns/static/add -d '{"name":"live.lan","type":"TXT","text":"keep"}' >/dev/null
routeros_api ip/dns/static/add -d '{"name":"lan","type":"TXT","text":"keep"}' >/dev/null
routeros_api certificate/add -d '{"name":"live","common-name":"router.lan","key-size":"prime256v1"}' >/dev/null
routeros_api certificate/sign -d '{".id":"live"}' >/dev/null
routeros_api ip/service/set -d '{".id":"api-ssl","certificate":"live"}' >/dev/null
routeros_fingerprint=$(routeros_api 'certificate?name=live' | json_field fingerprint)
routeros_version=$(routeros_api system/resource | json_field version)

echo "live-providers: Technitium ($TECHNITIUM_IMAGE), Gravity ($GRAVITY_IMAGE), AdGuard Home ($ADGUARDHOME_IMAGE), Pi-hole ($PIHOLE_IMAGE), BIND ($BIND_IMAGE), Pebble ($PEBBLE_IMAGE), OpenWrt ($OPENWRT_IMAGE), UniFi Network ($UNIFI_IMAGE), RouterOS $routeros_version"

export IPV6DDNS_LIVE_TECHNITIUM="{\"address\":\"$technitium\",\"token\":\"$technitium_token\",\"zone\":\"$zone\",\"ttl\":\"5m\"}"
export IPV6DDNS_LIVE_TECHNITIUM_DNS="127.0.0.1:$(port technitium 53/udp)"
export IPV6DDNS_LIVE_GRAVITY="{\"server\":\"$gravity\",\"api_key\":\"$password\",\"zone\":\"$zone.\",\"ttl\":\"5m\"}"
export IPV6DDNS_LIVE_GRAVITY_DNS="127.0.0.1:$(port gravity 53/udp)"
export IPV6DDNS_LIVE_ADGUARDHOME="{\"address\":\"$adguardhome\",\"username\":\"admin\",\"password\":\"$password\",\"zone\":\"$zone\"}"
export IPV6DDNS_LIVE_ADGUARDHOME_DNS="127.0.0.1:$(port adguardhome 53/udp)"
export IPV6DDNS_LIVE_PIHOLE="{\"address\":\"$pihole\",\"password\":\"$password\",\"zone\":\"$zone\"}"
export IPV6DDNS_LIVE_PIHOLE_DNS="127.0.0.1:$(port pihole 53/udp)"
export IPV6DDNS_LIVE_RFC2136="{\"server\":\"127.0.0.1:$(port bind 53/tcp)\",\"zone\":\"$zone\",\"ttl\":\"5m\",\"tsig_key\":\"live-key\",\"tsig_secret\":\"$bind_secret\"}"
export IPV6DDNS_LIVE_RFC2136_DNS="127.0.0.1:$(port bind 53/udp)"
export IPV6DDNS_LIVE_PEBBLE="$pebble/dir"
export IPV6DDNS_LIVE_PEBBLE_MANAGEMENT="https://127.0.0.1:$(port bind 15000/tcp)"
export IPV6DDNS_LIVE_PEBBLE_CA="$work/pebble-ca.pem"
export IPV6DDNS_LIVE_ACME_NETWORK="container:$prefix-bind"
export IPV6DDNS_LIVE_ACME_HOST="$acme_host"
export IPV6DDNS_LIVE_CERTBOT_IMAGE="$CERTBOT_IMAGE" IPV6DDNS_LIVE_LEGO_IMAGE="$LEGO_IMAGE" IPV6DDNS_LIVE_ACMESH_IMAGE="$ACMESH_IMAGE" IPV6DDNS_LIVE_KEA_IMAGE="$KEA_IMAGE"
export IPV6DDNS_LIVE_OPENWRT="{\"address\":\"127.0.0.1:$openwrt_ssh\",\"username\":\"root\",\"ssh_key\":\"$work/key\",\"host_key\":\"${openwrt_host_keys%% *}\",\"zone\":\"lan\"}"
export IPV6DDNS_LIVE_OPENWRT_DNS="127.0.0.1:$(port openwrt 53/udp)"
export IPV6DDNS_LIVE_OPENWRT_HOST_KEYS="$openwrt_host_keys"
routeros_settings="\"username\":\"admin\",\"password\":\"\",\"zone\":\"lan\",\"ttl\":\"5m\""
export IPV6DDNS_LIVE_MIKROTIK="{\"address\":\"127.0.0.1:$(port routeros 8728/tcp)\",$routeros_settings}"
export IPV6DDNS_LIVE_MIKROTIK_TLS="{\"address\":\"127.0.0.1:$(port routeros 8729/tcp)\",\"use_tls\":true,\"tls_fingerprint\":\"$routeros_fingerprint\",$routeros_settings}"
export IPV6DDNS_LIVE_MIKROTIK_DNS="127.0.0.1:$(port routeros 53/udp)"
export IPV6DDNS_LIVE_UNIFI="{\"address\":\"$unifi\",\"username\":\"admin\",\"password\":\"$password\",\"zone\":\"$zone\",\"tls_fingerprint\":\"$unifi_fingerprint\"}"

# One package at a time: they share the servers, and their zones. What the authority and its DNS
# server said, when a test failed: of the containers that are gone after.
if ! go test -tags live -count=1 -p 1 -v -run '^TestLive' "$@" ./ddns ./pkg/acme .; then
	for c in pebble bind; do
		echo "live-providers: the last of $c's log:" >&2
		docker logs --tail 60 "$prefix-$c" 2>&1 | sed "s/^/  $c: /" >&2
	done
	exit 1
fi

# What no DNS query shows: the static lease of the name the updates were of is still OpenWrt's.
if [ "$(docker exec "$prefix-openwrt" uci get dhcp.fixture_host.ip)" != 192.0.2.99 ]; then
	echo "live-providers: the host section of live.lan, not a domain section, is gone" >&2
	exit 1
fi
