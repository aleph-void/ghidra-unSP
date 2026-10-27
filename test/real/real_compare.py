#!/usr/bin/env python3
"""real_compare.py <ghidra .dis> <unidasm output>: every instruction Ghidra found must decode to the same
text as MAME's unidasm at the same address (jump targets compared as absolute word addresses)."""
import re, sys

def canon(t, mame):
    if mame:
        t = re.sub(r"\b(asr|lsl|lsr|rol|ror) (\d+)\b", lambda m: m.group(1) + " D" + m.group(2), t)
        if t.split()[0] in ("tstb", "setb", "clrb", "invb") or t.startswith("MR = ["):
            t = re.sub(r"(, ?)(\d+)$", lambda m: m.group(1) + "D" + m.group(2), t)
        t = re.sub(r"\bD(\d+)\b", lambda m: "#" + m.group(1), t)
        t = re.sub(r"(?<![#\w])([0-9a-f]+)\b", lambda m: "#%d" % int(m.group(1), 16), t)
    else:
        t = re.sub(r"0x([0-9a-f]+)", lambda m: "#%d" % int(m.group(1), 16), t)
        t = re.sub(r"(?<![\w#])(\d+)\b", lambda m: "#" + m.group(1), t)
    return re.sub(r"\s+", "", t).lower()

mame = {}
for ln in open(sys.argv[2]):
    m = re.match(r"^([0-9a-f]+): (.*)$", ln.rstrip())
    if m:
        mame[int(m.group(1), 16)] = m.group(2)
bad = n = 0
for ln in open(sys.argv[1]):
    a, h, t = ln.rstrip("\n").split(" ", 2)
    a = int(a, 16)
    n += 1
    if a not in mame or canon(mame[a], True) != canon(t, False):
        bad += 1
        print("DIFF @%x  ghidra: %s   mame: %s" % (a, t, mame.get(a)))
print("listing vs unidasm: %d instructions compared, %d differ" % (n, bad))
sys.exit(1 if bad else 0)
