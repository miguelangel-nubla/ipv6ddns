#!/bin/sh
# Makes the Homebrew formula of a version: in the file given, the formula of the tap
# miguelangel-nubla/homebrew-tap, the source is the one of the tag given, and the checksum its
# own. The formula builds from that source, so there is nothing else of a version in it.
#
#	tools/homebrew-formula.sh v1.2.3 ../homebrew-tap/Formula/ipv6ddns.rb
#
# The release does it, with the tap it clones; by hand, it is for a release that didn't.
set -eu
tag=$1 formula=$2

url="https://github.com/miguelangel-nubla/ipv6ddns/archive/refs/tags/$tag.tar.gz"
sha=$(curl -fsSL "$url" | shasum -a 256 | cut -d' ' -f1)

# Each of the two lines, once: a formula that has them otherwise is not changed in part.
[ "$(grep -c '^  url "' "$formula")" = 1 ] && [ "$(grep -c '^  sha256 "' "$formula")" = 1 ] || {
	echo "homebrew-formula: $formula has not one url and one sha256" >&2
	exit 1
}
tmp=$(mktemp)
sed -E "s|^  url \".*\"\$|  url \"$url\"|; s|^  sha256 \".*\"\$|  sha256 \"$sha\"|" "$formula" >"$tmp"
cat "$tmp" >"$formula"
rm -f "$tmp"
echo "homebrew-formula: $formula is of $tag, $sha"
