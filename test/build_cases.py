#!/usr/bin/env python3
"""Turns emu/cases.src into emu/cases.txt: 'asm' lines are assembled with naken_asm (independent assembler,
used as a black box; needs NAKEN_ASM=<path>), 'hex' lines are copied; the MAME disassembly of every case is
added as a comment so the intended instruction can be checked.

usage: build_cases.py <cases.src> <cases.txt>
Directives other than asm/hex are copied unchanged.  'asm' lines are assembled at word address 0x800
(or the case's 'at' address) with labels resolved by naken_asm.
"""
import os, re, subprocess, sys, tempfile

src, dst = sys.argv[1], sys.argv[2]
naken = os.environ.get("NAKEN_ASM", "naken_asm")
cases, cur = [], None
for ln in open(src):
    raw = ln.rstrip("\n")
    s = raw.strip()
    if s.startswith("#"):
        continue
    if not s.startswith("asm "):
        s = s.split("#")[0].strip()
    if s.startswith("case "):
        cur = {"head": raw, "lines": [], "asm": [], "hex": [], "at": 0x800}
        cases.append(cur)
    elif cur is None:
        continue
    elif s == "end":
        continue
    elif s.startswith("asm "):
        cur["asm"].append(s[4:].strip())
    elif s.startswith("hex "):
        cur["hex"].append(s[4:].replace(" ", ""))
    elif s.startswith("at "):
        cur["at"] = int(s.split()[1], 16)
        cur["lines"].append(raw)
    elif s:
        cur["lines"].append(raw)

def mame(code_hex):
    d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
    p = os.path.join(d, "c.bin")
    open(p, "wb").write(bytes.fromhex(code_hex))
    out = subprocess.run(["unidasm", p, "-arch", "unsp20", "-xchbytes", "-norawbytes", "-basepc", "%x" % 0x800],
                         capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if l.strip()]

out = []
for c in cases:
    code = ""
    if c["asm"]:
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        a = os.path.join(d, "c.asm")
        with open(a, "w") as f:
            f.write(".unsp\n.org 0x%x\n" % c["at"])
            f.write("\n".join(c["asm"]) + "\n")
        r = subprocess.run([naken, "-l", "-type", "bin", "-o", os.path.join(d, "c.bin"), a],
                           capture_output=True, text=True, cwd=d)
        if "Failed" in r.stdout or not os.path.exists(os.path.join(d, "c.bin")):
            sys.exit("assembler failed for %s:\n%s" % (c["head"], r.stdout[-800:]))
        code = open(os.path.join(d, "c.bin"), "rb").read().hex()
    elif c["hex"]:
        code = "".join(c["hex"])
    out.append(c["head"])
    for a in c["asm"]:
        out.append("# asm: " + a)
    for l in mame(code):
        out.append("# mame: " + l)
    out.extend(c["lines"])
    out.append("code " + code)
    out.append("end")
    out.append("")
open(dst, "w").write("\n".join(out))
