# After an upgrade, on Arch: the service is restarted, when it runs. Without systemd, as in a
# container, there is no service to tell.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
	systemctl try-restart ipv6ddns.service
fi
