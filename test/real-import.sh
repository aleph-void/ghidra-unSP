#!/usr/bin/env bash
# real-import.sh <binary> <base-word-address-hex> <outprefix> <seed-hex> ...   (GHIDRA_INSTALL_DIR set)
# Imports a raw word image with the unSP language, seeds functions, runs auto-analysis and RealCheck.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(readlink -f "$1"); BASE=$2; PFX=$(readlink -m "$3"); shift 3
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/unsp-real.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" -loader BinaryLoader \
	-loader-baseAddr "0x$BASE" -processor "${LANG_ID:-unsp:LE:16:default}" -scriptPath "$HERE" \
	-preScript SeedEntries.java "$@" -postScript RealCheck.java "$PFX" 60 -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
cat "$PFX.summary"
