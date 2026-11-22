#!/bin/sh
# The start of the Home Assistant app: the configuration is config.yaml in the app's folder,
# addon_configs/<id>_ipv6ddns (app_configs in recent versions), at /config here. It has all the
# settings, as in any other install: the level of the log, and where the report is served, which
# the starting configuration has for the app's page.
set -eu

config=/config/config.yaml
if [ ! -f "$config" ]; then
	cp /usr/share/ipv6ddns/config.yaml "$config"
	echo "ipv6ddns: no configuration yet: wrote a starting one, config.yaml in the app's folder, addon_configs/<id>_ipv6ddns (app_configs in recent versions). Edit it, and restart the app." >&2
fi

exec ipv6ddns -config_file "$config"
