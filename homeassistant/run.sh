#!/bin/sh
# The start of the Home Assistant add-on: the configuration is config.yaml in the add-on's folder,
# /addon_configs/<id>_ipv6ddns, at /config here; the add-on's options are /data/options.json.
set -eu

config=/config/config.yaml
if [ ! -f "$config" ]; then
	cp /usr/share/ipv6ddns/config.yaml "$config"
	echo "ipv6ddns: no configuration yet: wrote a starting one, config.yaml in the add-on's folder of /addon_configs. Edit it, and restart the add-on." >&2
fi

log_level=$(jq -r '.log_level // "info"' /data/options.json 2>/dev/null || echo info)

# INGRESS_LISTEN, to try it outside Home Assistant. The report through Home Assistant only: the Supervisor reaches an add-on of the host's network at
# the host's address on its own network, which the network outside doesn't reach.
exec ipv6ddns -config_file "$config" -log_level "$log_level" -webserver_listen "${INGRESS_LISTEN:-172.30.32.1:8053}"
