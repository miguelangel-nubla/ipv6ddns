#!/bin/sh
# After the package's files are in place, on Alpine. An install starts nothing: the
# configuration is the user's to write first.
echo "ipv6ddns: edit /etc/ipv6ddns/config.yaml, and then: rc-update add ipv6ddns default && rc-service ipv6ddns start"
