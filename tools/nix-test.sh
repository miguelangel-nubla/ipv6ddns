#!/bin/sh
# The flake, checked as nix flake check does, from any system with Docker: in a container of
# Nix's, thrown away, with its store kept in a volume. The package builds, and on Linux the
# module's service runs in a machine of NixOS, and discovers another on its network.
#
# The package has the hash of the Go modules, which is behind after any change of go.sum: the
# check fails then, and this writes the one that is:
#
#	tools/nix-test.sh --update
#
# Other arguments go to nix flake check.
set -eu
cd "$(dirname "$0")/.."

# The machines of the test are virtual: with the processor's help where there is, as on CI, and
# without it, slowly.
kvm=""
[ ! -e /dev/kvm ] || kvm="--device /dev/kvm"

# shellcheck disable=SC2086 # kvm is words, or none.
nix() {
	docker run --rm --privileged $kvm -v "$PWD":/src -w /src -v ipv6ddns-nix:/nix nixos/nix:latest sh -euc '
		# The checkout is another user'"'"'s than the container'"'"'s, which git minds.
		git config --global --add safe.directory /src
		exec nix --extra-experimental-features "nix-command flakes" --option system-features "kvm nixos-test benchmark big-parallel" "$@"
	' sh "$@"
}

if [ "${1:-}" = --update ]; then
	# With no hash it can have, the build of the modules tells the one they have.
	sed -i.bak -E 's|^  vendorHash = .*;$|  vendorHash = lib.fakeHash;|' nix/package.nix
	rm -f nix/package.nix.bak
	hash=$(nix build --no-link .#default 2>&1 | sed -n 's/^ *got: *\(sha256-[A-Za-z0-9+/=]*\)$/\1/p' | tail -1)
	[ -n "$hash" ] || {
		echo "nix-test: the build told no hash of the modules" >&2
		exit 1
	}
	sed -i.bak -E "s|^  vendorHash = .*;\$|  vendorHash = \"$hash\";|" nix/package.nix
	rm -f nix/package.nix.bak
	echo "nix-test: the modules are $hash"
	exit 0
fi

nix flake check -L "$@"
echo "nix-test: ok"
