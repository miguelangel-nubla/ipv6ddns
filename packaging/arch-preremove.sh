# Before the package's files are removed, on Arch: the service is stopped, and left out of the
# boot. An upgrade doesn't run this.
if [ -d /run/systemd/system ]; then
	systemctl disable --now ipv6ddns.service
fi
