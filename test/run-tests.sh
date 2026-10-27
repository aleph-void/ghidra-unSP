#!/usr/bin/env bash
# Runs every u'nSP check that needs no non-redistributable input.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/unSP> \
#     test/run-tests.sh [--real] <workdir>
#
# Needs: MAME's `unidasm` on PATH (the decode oracle, used as a black box), python3, a JDK for Ghidra.
# --real also fetches and builds naken_asm (pinned commit + SHA-256; the independent assembler), checks the
# emulator cases are reproducible from their assembler source, runs the assembler round trip and imports,
# analyses and decompiles the assembled test programs.  Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "$1" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
command -v unidasm >/dev/null || { echo "unidasm (MAME) not found on PATH" >&2; exit 2; }
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }
L=unsp:LE:16:default

step "the generator reproduces the checked-in SLEIGH"
python3 "$MOD/tools/gen_unsp.py" "$W/unsp.slaspec"
ok diff -q "$W/unsp.slaspec" "$MOD/data/languages/unsp.slaspec"

step "spec compiles (sleigh -l: no unresolved pattern conflicts), .sla < 16 MB"
out=$(cd "$W" && cp "$MOD"/data/languages/unsp.slaspec . && "$GHIDRA_INSTALL_DIR/support/sleigh" -l unsp.slaspec 2>&1)
if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo "FAILED: compile"; fail=1; else echo "compiles, no conflicts"; fi
sz=$(stat -c %s "$W/unsp.sla"); echo ".sla size: $sz bytes"; ((sz < 16000000)) || { echo "FAILED: .sla too big"; fail=1; }

step "decode vs MAME unidasm unsp20 (every first word x 2 second words; extended group: prefix 0xff80 x every second word x 2 third words)"
ok python3 "$HERE/diff_mame.py" "$W/dm20" $L unsp20
ok python3 "$HERE/diff_mame.py" "$W/dmx" $L unsp20 --prefix 0xff80
step "decode vs unsp12 and unsp10 (instructions of the newer versions must equal unsp20's)"
ok python3 "$HERE/diff_mame.py" "$W/dm12" $L unsp12 --newer unsp20
ok python3 "$HERE/diff_mame.py" "$W/dm10" $L unsp10 --newer unsp20
step "decode check can fail (a corrupted result must be reported)"
if python3 "$HERE/diff_mame.py" "$W/dmb" $L unsp20 --break >/dev/null; then
	echo "FAILED: the broken result was not detected"; fail=1; else echo "broken result detected"; fi

step "every constructor is reached"
cat "$W/dm20/cases.hex" "$W/dmx/cases.hex" > "$W/ee.hex"
out=$("$HERE/every-entry.sh" $L "$W/ee.hex" "$W/ee.txt")
echo "$out"
grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }

step "p-code: hand-computed emulator cases (and a deliberately wrong expectation)"
ok "$HERE/emu-test.sh" $L "$HERE/emu/cases.txt" "$W/emu"
grep -c "^case" "$HERE/emu/cases.txt" | sed 's/^/emulator cases: /'

if ((REAL)); then
	step "naken_asm (independent assembler)"
	export NAKEN_ASM=$("$HERE/build-naken.sh" "$W/naken") || { echo "FAILED: build naken_asm"; exit 1; }
	step "emulator cases are reproducible from their assembler source"
	python3 "$HERE/build_cases.py" "$HERE/emu/cases.src" "$W/cases.txt" && ok diff -q "$W/cases.txt" "$HERE/emu/cases.txt"
	step "assembler round trip (every addressing form of every ALU operation)"
	ok python3 "$HERE/asm_forms.py" "$W/af" $L
	step "assembled programs: import, analysis, decompile, listing vs unidasm"
	ok "$HERE/real-check.sh" "$W/real" $L
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
