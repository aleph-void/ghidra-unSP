#!/usr/bin/env python3
"""Buckets the differences saved by diff_mame.py by instruction shape: bucket.py <diff.json> [N]"""
import json, re, sys, collections
d = json.load(open(sys.argv[1]))
n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
def shape(t):
    s = re.sub(r"\b(r[1-4]|sp|bp|sr|pc)\b", "R", t)
    s = re.sub(r"0x[0-9a-f]+|(?<![a-z])[0-9a-f]{2,6}(?![a-z])", "N", s)
    s = re.sub(r"\b\d+\b", "N", s)
    return re.sub(r"\s+", "", s)
for cls, items in d.items():
    b = collections.defaultdict(list)
    for h, m, g in items:
        b[(shape(m), shape(g))].append((h, m, g))
    print("==", cls, len(items), "in", len(b), "buckets")
    for k, v in sorted(b.items(), key=lambda kv: -len(kv[1])):
        print("%5d  %s  ||  %s    e.g. %s" % (len(v), k[0][:40], k[1][:50], v[:n]))
