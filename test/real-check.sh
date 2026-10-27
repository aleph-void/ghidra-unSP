#!/usr/bin/env bash
# Real-code check: assembles test/real/progs.asm with naken_asm, imports the image headless with the unSP
# language, auto-analyses and decompiles it, and compares Ghidra's instructions with MAME's unidasm at the
# same addresses.
#   GHIDRA_INSTALL_DIR=... NAKEN_ASM=... test/real-check.sh <workdir> [lang-id]
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}" "${NAKEN_ASM:?set NAKEN_ASM}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
export LANG_ID=${2:-unsp:LE:16:default}
"$NAKEN_ASM" -l -type bin -o "$W/progs.bin" "$HERE/real/progs.asm" >/dev/null
"$HERE/real-import.sh" "$W/progs.bin" 1000 "$W/progs" 1000 > "$W/progs.out"
cat "$W/progs.out"
unidasm "$W/progs.bin" -arch unsp20 -xchbytes -norawbytes -basepc 1000 > "$W/progs.mame"
python3 "$HERE/real/real_compare.py" "$W/progs.dis" "$W/progs.mame"
