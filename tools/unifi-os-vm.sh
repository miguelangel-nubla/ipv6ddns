#!/bin/sh
# A Debian VM with UniFi OS Server, for the live tests of the unifi provider and plugin on a
# machine that can't run it itself, as macOS: QEMU, of the machine's own architecture, with HVF or
# KVM. tools/unifi-os-server.sh sets the server up in it.
#
#	tools/unifi-os-vm.sh up [dir]     make the VM, or start it, and set the server up: the tests'
#	                                  variables are in dir/env, for the console at 127.0.0.1:18444
#	tools/unifi-os-vm.sh stop [dir]   power it off
#	tools/unifi-os-vm.sh ssh [dir]    a shell in it
#
# dir is ~/.cache/ipv6ddns-unifi-os-vm unless given. The VM is of Debian 13, or of the cloud image
# that UNIFI_OS_VM_IMAGE has the URL of, as Ubuntu's, of CI's runners, when it's made. It needs QEMU,
# curl, OpenSSL, OpenSSH, and an ISO maker: hdiutil on macOS, or xorriso, genisoimage or mkisofs.
set -eu
cd "$(dirname "$0")/.."
tools=$(pwd)/tools

action=${1:?usage: tools/unifi-os-vm.sh up|stop|ssh [dir]}
dir=${2:-$HOME/.cache/ipv6ddns-unifi-os-vm}
mkdir -p "$dir"
cd "$dir"

ssh_vm() {
	ssh -q -i key -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 debian@127.0.0.1 "$@"
}

case $(uname -m) in
arm64 | aarch64) arch=arm64 qemu=qemu-system-aarch64 machine=virt firmware=edk2-aarch64-code.fd ;;
x86_64 | amd64) arch=amd64 qemu=qemu-system-x86_64 machine=q35 firmware= ;;
*)
	echo "unifi-os-vm: no VM of $(uname -m)" >&2
	exit 1
	;;
esac
case $(uname -s) in
Darwin) accel=hvf ;;
*) accel=kvm ;;
esac

start() {
	[ -f qemu.pid ] && kill -0 "$(cat qemu.pid)" 2>/dev/null && return
	set -- -machine "$machine,accel=$accel" -cpu host -smp 4 -m 6144 \
		-drive if=virtio,format=qcow2,file=disk.qcow2 \
		-drive if=virtio,format=raw,media=cdrom,readonly=on,file=seed.iso \
		-netdev user,id=n0,hostfwd=tcp:127.0.0.1:2223-:22,hostfwd=tcp:127.0.0.1:18444-:11443 \
		-device virtio-net-pci,netdev=n0 -display none -serial file:serial.log -daemonize -pidfile qemu.pid
	if [ -n "$firmware" ]; then
		code=$(dirname "$(command -v "$qemu")")/../share/qemu/$firmware
		[ -f vars.fd ] || dd if=/dev/zero of=vars.fd bs=1m count=64 2>/dev/null || dd if=/dev/zero of=vars.fd bs=1M count=64
		set -- -drive "if=pflash,format=raw,readonly=on,file=$code" -drive if=pflash,format=raw,file=vars.fd "$@"
	fi
	"$qemu" "$@"
}

case $action in
up)
	if [ ! -f disk.qcow2 ]; then
		echo "unifi-os-vm: making the VM in $dir" >&2
		curl -fsSL -o debian.qcow2 "${UNIFI_OS_VM_IMAGE:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-$arch.qcow2}"
		qemu-img create -q -f qcow2 -b debian.qcow2 -F qcow2 disk.qcow2 32G
		[ -f key ] || ssh-keygen -q -t ed25519 -N "" -f key -C ipv6ddns-unifi-os-vm
		mkdir -p seed
		printf 'instance-id: ipv6ddns-unifi-os-vm\nlocal-hostname: unifi-os\n' >seed/meta-data
		cat >seed/user-data <<EOF
#cloud-config
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $(cat key.pub)
package_update: true
packages:
  - podman
  - slirp4netns
  - uidmap
  - passt
  - curl
  - openssl
  - python3
EOF
		if command -v hdiutil >/dev/null; then
			hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o seed.iso seed
		else
			iso=$(command -v xorriso genisoimage mkisofs | head -1)
			case $iso in
			*xorriso) xorriso -as mkisofs -quiet -V cidata -J -r -o seed.iso seed ;;
			?*) "$iso" -quiet -V cidata -J -r -o seed.iso seed ;;
			*)
				echo "unifi-os-vm: no ISO maker: install xorriso" >&2
				exit 1
				;;
			esac
		fi
	fi
	start
	# Ten minutes for it to boot: a machine that never does is told, not waited for.
	booted=no
	for _ in $(seq 120); do
		if ssh_vm true 2>/dev/null; then
			booted=yes
			break
		fi
		sleep 5
	done
	[ "$booted" = yes ] || {
		echo "unifi-os-vm: the machine did not answer over SSH in ten minutes" >&2
		exit 1
	}
	ssh_vm 'cloud-init status --wait >/dev/null'
	scp -q -i key -P 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$tools/unifi-os-server.sh" debian@127.0.0.1:
	# The variables of the console as the host reaches it, through the forwarded port.
	# An empty one is none: sent, it would take the admin's password from the machine's.
	[ -s env ] && sed 's/127\.0\.0\.1:18444/127.0.0.1:11443/g' env | ssh_vm 'cat > unifi-os.env'
	# Not through a pipe, whose status is its last command's: a setup that failed would leave
	# an empty file here in place of the variables, as if it had passed.
	ssh_vm 'sh unifi-os-server.sh unifi-os.env && cat unifi-os.env' >env.vm
	sed 's/127\.0\.0\.1:11443/127.0.0.1:18444/g' env.vm >env.new
	rm -f env.vm
	mv env.new env
	echo "unifi-os-vm: the variables are in $dir/env" >&2
	;;
stop)
	[ -f qemu.pid ] || exit 0
	pid=$(cat qemu.pid)
	ssh_vm 'sudo poweroff' 2>/dev/null || true
	for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
	kill "$pid" 2>/dev/null || true
	rm -f qemu.pid
	;;
ssh)
	ssh_vm
	;;
*)
	echo "usage: tools/unifi-os-vm.sh up|stop|ssh [dir]" >&2
	exit 2
	;;
esac
