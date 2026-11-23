#!/bin/sh
# After an upgrade, on Alpine: the service is restarted, when it runs.

# Without OpenRC running, as in a container, there is no service to tell.
[ -e /run/openrc/softlevel ] || exit 0

rc-service --quiet --ifstarted ipv6ddns restart
