# After the package's files are removed, on Arch: systemd forgets the unit.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi
