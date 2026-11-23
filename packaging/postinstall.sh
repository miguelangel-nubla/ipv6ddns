#!/bin/sh
# After the package's files are in place. A first install starts nothing: the configuration is
# the user's to write first. An upgrade restarts the service, when it runs.
set -e

# The first argument: of a deb, configure, with the version before as the second, when there
# was one; of an rpm, 1 at an install and 2 at an upgrade.
upgrade=no
case "$1" in
configure) [ -z "${2:-}" ] || upgrade=yes ;;
2) upgrade=yes ;;
esac

# Without systemd, as in a container, there is no service to tell.
[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload
if [ "$upgrade" = yes ]; then
	systemctl try-restart ipv6ddns.service
else
	echo "ipv6ddns: edit /etc/ipv6ddns/config.yaml, and then: systemctl enable --now ipv6ddns"
fi
