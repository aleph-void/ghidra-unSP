#!/usr/bin/env bash
# Fetches (pinned commit + SHA-256) and builds naken_asm, the independent u'nSP assembler.  Prints its path.
#   test/build-naken.sh <workdir>
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
SHA=247c23706909f09bac77c587780b8a826bbda27c
TGZ_SHA256=b3b2bada7bc0b5ac1194b26c31bee9d2396c44a21c48dc2808ddefe8a5eb9b10
if [[ ! -x $W/naken_asm-$SHA/naken_asm ]]; then
	curl -sSL -o "$W/naken.tgz" "https://github.com/mikeakohn/naken_asm/archive/$SHA.tar.gz"
	echo "$TGZ_SHA256  $W/naken.tgz" | sha256sum -c - >&2
	tar -C "$W" -xzf "$W/naken.tgz"
	(cd "$W/naken_asm-$SHA" && ./configure >/dev/null 2>&1 && make -j"$(nproc)" >/dev/null 2>&1)
fi
echo "$W/naken_asm-$SHA/naken_asm"
