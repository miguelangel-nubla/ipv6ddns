#!/bin/sh
# After the package's files are removed: systemd forgets the unit.
set -e

[ -d /run/systemd/system ] || exit 0

systemctl daemon-reload
