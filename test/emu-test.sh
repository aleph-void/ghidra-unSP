#!/usr/bin/env bash
# P-code emulation test: test/emu-test.sh <language-id> [cases.txt] [outdir]
# Exit status 0 only if every case passes and the deliberately broken expectation is detected.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1
CASES=$(readlink -f "${2:-$HERE/emu/cases.txt}")
OUTD=$(readlink -m "${3:-${TMPDIR:-/tmp}/unsp-emu}")
mkdir -p "$OUTD"
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/unsp-emu.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
head -c 65536 /dev/zero > "$PROJ/zero.bin"
out="$OUTD/emu.txt"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" \
	-loader BinaryLoader -loader-baseAddr 0 -processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript EmuTest.java "$CASES" "$out" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $out ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
grep -v "^PASS (broken" "$out" | grep -v "^PASS " || true
grep -q " 0 failed, broken expectation detected" "$out"
