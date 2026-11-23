#!/bin/sh
# Before the package's files are removed, on Alpine: the service is stopped, and left out of
# the boot. An upgrade doesn't run this.

[ -e /run/openrc/softlevel ] || exit 0

rc-service --quiet --ifstarted ipv6ddns stop
# In whichever runlevels it was added to.
rc-update --quiet --all del ipv6ddns 2>/dev/null || true
