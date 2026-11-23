#!/bin/sh
# Before the package's files are removed. A removal stops the service, and an upgrade leaves it
# running: the new version restarts it.
set -e

# The first argument: of a deb, remove, or upgrade; of an rpm, 0 at a removal and 1 at an upgrade.
case "$1" in
remove | 0) ;;
*) exit 0 ;;
esac

[ -d /run/systemd/system ] || exit 0

systemctl disable --now ipv6ddns.service
