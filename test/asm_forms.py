#!/usr/bin/env python3
"""Assembler round trip: every addressing form of every ALU operation is written in naken_asm syntax (an
independent assembler, used as a black box), assembled, decoded by Ghidra, and the Ghidra text is compared
with the text the assembler source implies.

usage: asm_forms.py <workdir> <language-id>      (NAKEN_ASM=<path to naken_asm>, GHIDRA_INSTALL_DIR set)
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
work, lang = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
naken = os.environ.get("NAKEN_ASM", "naken_asm")

OPS = {  # naken mnemonic -> (ghidra operator, carry flag, kind)
    "add": ("+=", False), "adc": ("+=", True), "sub": ("-=", False), "sbc": ("-=", True),
    "and": ("&=", False), "or": ("|=", False), "xor": ("^=", False), "ld": ("=", False),
    "neg": ("=-", False),
}
BIN = {"add": "+", "adc": "+", "sub": "-", "sbc": "-", "and": "&", "or": "|", "xor": "^"}
cases = []   # (asm, expected)


def car(m):
    return ", carry" if m in ("adc", "sbc") else ""


for m, (op, _) in OPS.items():
    c = car(m)
    # one-word forms: rd = r2, source variants
    for src, text in (("r3", "r3"), ("#5", "0x5"), ("#33", "0x21"), ("[r3]", "[r3]"), ("[r3++]", "[r3++]"),
                      ("[r3--]", "[r3--]"), ("[++r3]", "[++r3]"), ("d:[r3]", "ds:[r3]"), ("d:[r3++]", "ds:[r3++]"),
                      ("d:[r3--]", "ds:[r3--]"), ("d:[++r3]", "ds:[++r3]"), ("[bp+17]", "[bp+0x11]"),
                      ("[40]", "[0x28]"), ("r3 asr 2", "r3 asr 2"), ("r3 lsl 3", "r3 lsl 3"),
                      ("r3 lsr 1", "r3 lsr 1"), ("r3 rol 4", "r3 rol 4"), ("r3 ror 2", "r3 ror 2")):
        if m == "neg" and src.startswith("#") and False:
            continue
        cases.append((f"{m} r2,{src}", f"r2 {op} {text}{c}"))
    # two word forms
    if m in BIN:
        cases.append((f"{m} r2,r3,#4660", f"r2 = r3 {BIN[m]} 0x1234{c}"))
        cases.append((f"{m} r2,r3,[4660]", f"r2 = r3 {BIN[m]} [0x1234]{c}"))
        cases.append((f"{m} [4660],r2,r3", f"[0x1234] = r2 {BIN[m]} r3{c}"))
    if m == "ld":
        cases.append(("ld r2,#4660", "r2 = 0x1234"))
        cases.append(("ld r2,[4660]", "r2 = [0x1234]"))
for m in ("cmp", "test"):
    for src, text in (("r3", "r3"), ("#5", "0x5"), ("[r3]", "[r3]"), ("[bp+17]", "[bp+0x11]"), ("[40]", "[0x28]"),
                      ("d:[r3++]", "ds:[r3++]"), ("r3 ror 2", "r3 ror 2")):
        cases.append((f"{m} r2,{src}", f"{m} r2,{text}"))
for src, text in (("[r3]", "[r3]"), ("[r3++]", "[r3++]"), ("[++r3]", "[++r3]"), ("d:[r3--]", "ds:[r3--]"),
                  ("[bp+17]", "[bp+0x11]"), ("[40]", "[0x28]"), ("[4660]", "[0x1234]")):
    cases.append((f"st r2,{src}", f"{text} = r2"))
cases += [("retf", "retf"), ("reti", "reti"), ("break", "break"), ("int off", "int off"), ("int irq,fiq", "int fiq,irq"),
          ("fir_mov on", "fir_mov on"), ("irq on", "irq on"), ("fiq off", "fiq off"),
          ("mul.us r2,r3", "MR = r2*r3,us"), ("mul.ss r2,r3", "MR = r2*r3,ss"), ("mac.ss [r2],[r3],4", "MR = [r2]*[r3],ss,4"),
          ("mac.us [r1],[r2],16", "MR = [r1]*[r2],us,16"),
          ("push r2-r4,[sp]", "push r2, r4 to [sp]"), ("pop r2-r4,[sp]", "pop r3, r4 from [sp]") if False else ("pop r3,[r4]", "pop r3, r3 from [r4]")]

rows = []
bad_asm = []
for a, e in cases:
    src = os.path.join(work, "one.asm")
    with open(src, "w") as f:
        f.write(".unsp\n.org 0x1000\n" + a + "\n")
    out = os.path.join(work, "one.bin")
    if os.path.exists(out):
        os.remove(out)
    r = subprocess.run([naken, "-type", "bin", "-o", out, src], capture_output=True, text=True, cwd=work)
    if not os.path.exists(out) or "Failed" in r.stdout:
        bad_asm.append(a)
        rows.append(None)
        continue
    rows.append(open(out, "rb").read().hex())
hexf = os.path.join(work, "cases.hex")
good = [(c, h) for c, h in zip(cases, rows) if h]
with open(hexf, "w") as f:
    for c, h in good:
        f.write(h + "\n")
for a in bad_asm:
    print("not accepted by the assembler (skipped):", a)
cases = [c for c, h in good]
outf = os.path.join(work, "ghidra.out")
subprocess.run([os.path.join(HERE, "dis.sh"), lang, hexf, outf], check=True)
ghi = [ln.rstrip("\n").split(" ", 2) for ln in open(outf)]


def norm(t):
    t = re.sub(r"0x([0-9a-fA-F]+)", lambda m: "#%d" % int(m.group(1), 16), t)
    return re.sub(r"\s+", "", t).lower()


bad = 0
for (a, e), g in zip(cases, ghi):
    if norm(g[2]) != norm(e):
        bad += 1
        print("DIFF  %-24s expected %-28s ghidra %s  [%s]" % (a, e, g[2], g[0]))
print("assembler round trip: %d forms, %d differ" % (len(cases), bad))
sys.exit(1 if bad else 0)
