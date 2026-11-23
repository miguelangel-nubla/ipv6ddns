# After the package's files are in place, on Arch. An install starts nothing: the configuration
# is the user's to write first. A part of the function pacman calls, so it ends by itself.
echo "ipv6ddns: edit /etc/ipv6ddns/config.yaml, and then: systemctl enable --now ipv6ddns"
