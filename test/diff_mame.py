#!/usr/bin/env python3
"""Decode differential: Ghidra vs MAME unidasm (-arch unsp10|unsp12|unsp20), used as a black box.

usage: diff_mame.py <workdir> <language-id> <arch> [--second W ...] [--break] [--show N]
Corpus: every 16 bit first word x the given second words (default 0x1234 0xfedc).  Each record is laid
out in a stride-8 file for unidasm; the length unidasm reports truncates the record, Ghidra decodes the
distinct truncated byte strings at 0x1000 and the texts are compared after normalisation
(numbers -> integers, spacing removed; jump targets absolute in both).  --break corrupts one Ghidra
result: the run must then report a difference.
"""
import os, re, subprocess, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
work, lang, arch = args[0], args[1], args[2]
seconds, brk, show, base, prefix, newer = [0x1234, 0xfedc], False, 12, 0x1000, None, None
i = 3
while i < len(args):
    if args[i] == "--second":
        seconds = [int(args[i + 1], 0)]; i += 2
        while i < len(args) and not args[i].startswith("--"):
            seconds.append(int(args[i], 0)); i += 1
    elif args[i] == "--prefix":
        prefix = int(args[i + 1], 0); i += 2
    elif args[i] == "--newer":
        newer = args[i + 1]; i += 2
    elif args[i] == "--break":
        brk = True; i += 1
    elif args[i] == "--show":
        show = int(args[i + 1]); i += 2
    else:
        raise SystemExit("bad arg " + args[i])
os.makedirs(work, exist_ok=True)

recs = []
for w in range(65536):
    for s in seconds:
        recs.append((prefix.to_bytes(2, "little") if prefix is not None else b"") +
                    w.to_bytes(2, "little") + s.to_bytes(2, "little"))
binf = os.path.join(work, "rec.bin")
with open(binf, "wb") as f:
    for r in recs:
        f.write(r + b"\0" * (8 - len(r)))
# addresses are word addresses; the record k starts at word 4k.  basepc = the Ghidra address so that
# absolute jump targets agree (instruction i of a record is at base + 0, i.e. record start).
p = subprocess.run(["unidasm", binf, "-arch", arch, "-xchbytes", "-norawbytes", "-basepc", "0"],
                   capture_output=True, text=True, check=True)
addr_text = {}
order = []
for ln in p.stdout.splitlines():
    m = re.match(r"^([0-9a-f]+): (.*)$", ln)
    if m:
        a = int(m.group(1), 16)
        addr_text[a] = m.group(2).strip()
        order.append(a)
nxt = {order[k]: order[k + 1] for k in range(len(order) - 1)}
oracle = []
for k, r in enumerate(recs):
    a = k * 4
    t = addr_text.get(a)
    oracle.append((t, nxt.get(a, a + 1) - a))

newer_text = {}
if newer:
    # instructions the older architecture lacks must be ones the newer architecture's oracle decodes
    pn = subprocess.run(["unidasm", binf, "-arch", newer, "-xchbytes", "-norawbytes", "-basepc", "0"],
                        capture_output=True, text=True, check=True)
    for ln in pn.stdout.splitlines():
        m = re.match(r"^([0-9a-f]+): (.*)$", ln)
        if m:
            newer_text[int(m.group(1), 16)] = m.group(2).strip()

INVALID = re.compile(r"^<.*>$")
newer_used = set()
if newer:
    order_n = sorted(newer_text)
    nxt_n = {order_n[i]: order_n[i + 1] for i in range(len(order_n) - 1)}
    for k in range(len(recs)):
        t, n = oracle[k]
        if (t is None or INVALID.match(t) or t == "--") and 4 * k in newer_text:
            tn = newer_text[4 * k]
            if not (INVALID.match(tn) or tn == "--"):
                oracle[k] = (tn, nxt_n.get(4 * k, 4 * k + 1) - 4 * k)
                newer_used.add(k)
uniq = {}
for r, (t, n) in zip(recs, oracle):
    uniq[r[: 2 * n]] = None
hexf = os.path.join(work, "cases.hex")
with open(hexf, "w") as f:
    for r in uniq:
        f.write(r.hex() + "\n")
outf = os.path.join(work, "ghidra.out")
subprocess.run([os.path.join(HERE, "dis.sh"), lang, hexf, outf, "@%x" % base], check=True)
ghi = {}
for ln in open(outf):
    h, n, t = ln.rstrip("\n").split(" ", 2)
    ghi[bytes.fromhex(h)] = (int(n), t)
if brk:
    k0 = b"\x02\x01"   # r1 += r2
    ghi[k0] = (ghi[k0][0], ghi[k0][1] + " 0x7")

DECMN = ("tstb", "setb", "clrb", "invb")
SHIFTS = ("asr", "lsl", "lsr", "rol", "ror")


def num(tok):
    return str(int(tok, 16))


JUMPS = re.compile(r"^(j[a-z]+) ([0-9a-f]+)$")


def canon_mame(t, addr):
    t = re.sub(r"^\(Extended group( \d)?\) ", "", t.strip())
    mn = t.split()[0]
    m = JUMPS.match(t)
    if m:
        return m.group(1) + "T" + str((int(m.group(2), 16) - addr) & 0x3fffff)
    # decimal fields: shift counts, bit indices, multiply-accumulate count
    def dec_fix(s):
        s = re.sub(r"\b(asr|lsl|lsr|rol|ror) (\d+)\b", lambda m: m.group(1) + " D" + m.group(2), s)
        if mn in DECMN:
            s = re.sub(r",(\d+)$", lambda m: ",D" + m.group(1), s)
        if s.startswith("MR = ["):
            s = re.sub(r", (\d+)$", lambda m: ", D" + m.group(1), s)
        return s
    s = dec_fix(t)
    s = re.sub(r"\bD(\d+)\b", lambda m: "#" + m.group(1), s)  # mark decimals so they are not re-read as hex
    s = re.sub(r"(?<![#\w])([0-9a-f]+)\b", lambda m: "#" + str(int(m.group(1), 16)), s)
    s = re.sub(r"([\w\]])(\d+)\b", lambda m: m.group(0), s)
    return re.sub(r"\s+", "", s).lower()


def canon_ghidra(t):
    t = t.strip()
    m = re.match(r"^(j[a-z]+) 0x([0-9a-f]+)$", t)
    if m:
        return m.group(1) + "T" + str((int(m.group(2), 16) - base // 2) & 0x3fffff)
    s = re.sub(r"0x([0-9a-fA-F]+)", lambda m: "#" + str(int(m.group(1), 16)), t)
    # bare decimal digits printed by the language (shift counts, literal 1..4)
    s = re.sub(r"(?<![\w#])(\d+)\b", lambda m: "#" + m.group(1), s)
    return re.sub(r"\s+", "", s).lower()


def is_invalid(t):
    # MAME prints "--" for the blank-memory words 0x0000 and 0xffff
    return t is None or INVALID.match(t) is not None or t == "--"


agree = both_bad = explained = newer_ok = reassigned = blank = 0
cls = collections.defaultdict(list)
for k, (r, (t, n)) in enumerate(zip(recs, oracle)):
    key = r[: 2 * n]
    gn, gt = ghi.get(key, (0, "BAD"))
    mi, gi = is_invalid(t), gt == "BAD"
    if t is not None and re.match(r"^\(Extended group( \d)?\) <", t):
        mi = True
    if mi and gi:
        both_bad += 1
    elif mi and t == "--" and key[:2] in (b"\x00\x00", b"\xff\xff"):
        blank += 1   # MAME prints "--" for the blank-memory words 0x0000 and 0xffff
    elif mi and key[:2] == b"\x80\xff" and gn == 2 and re.sub(r"\s+", "", gt) == "MR=[pc]*[sp],ss,16":
        explained += 1   # 0xff80 not followed by a valid extended word: the v1.x multiply-accumulate
    elif mi:
        cls["ghidra-decodes-oracle-invalid"].append((key.hex(), t, gt))
    elif gi:
        cls["ghidra-undecoded"].append((key.hex(), t, gt))
    elif gn != 2 * n and key[:2] == b"\x80\xff" and gn > 2 and t == "MR = [pc]*[sp], ss, 16":
        explained += 1   # 0xff80 is the v2.0 extended-group prefix (the v1.x multiply-accumulate before)
    elif gn != 2 * n:
        cls["length"].append((key.hex(), t, gt))
    elif canon_mame(t, k * 4) == canon_ghidra(gt):
        if k in newer_used:
            newer_ok += 1   # not in this architecture version, present (and identical) in the newer one
        else:
            agree += 1
    elif newer and 4 * k in newer_text and canon_mame(newer_text[4 * k], 4 * k) == canon_ghidra(gt):
        reassigned += 1   # the encoding means something else in the newer version (v1.0 f0 20..38 = multiply)
    else:
        cls["text"].append((key.hex(), t, gt))
total = len(recs)
print("%s vs %s: records %d, distinct %d: agree %d, both-invalid %d, explained (0xff80 as v1.x muls) %d, newer-version instruction %d, reassigned in newer version %d, blank words %d, different %d" %
      (lang, arch, total, len(uniq), agree, both_bad, explained, newer_ok, reassigned, blank, sum(len(v) for v in cls.values())))
for k, v in cls.items():
    print("--", k, len(v))
    for e in v[:show]:
        print("   ", e)
import json
json.dump({k: v for k, v in cls.items()}, open(os.path.join(work, "diff.json"), "w"))
sys.exit(1 if cls else 0)
