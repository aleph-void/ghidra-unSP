# Ghidra-Rare notes: Sunplus / Generalplus u'nSP

Language `unsp:LE:16:default` (the original ID; one language covers u'nSP 1.0 - 1.3 and the 2.0 extended group).
Credits and the list of changes: [CREDITS.md](CREDITS.md). The module's README keeps the original text with the
limitation list updated.

## What it covers
Registers `sp r1-r4 bp sr pc` (SR = `DS[15:10] N Z S C CS[5:0]`; the flags are bit ranges of SR), the shadow bank
`sr1-sr4` (SECBANK), `r8-r15` (2.0), `fr`, the SB shift register, the interrupt-mode bits. 22-bit word-addressed
space (`ram`, wordsize 2). Every ALU form (`+= -= cmp =- ^= = |= &= test`, store), all addressing modes, the
two-word forms, shifts with SB, push/pop, call/goto/retf/reti/break, conditional jumps, multiply and inner product,
bit operations, `ds`/`fr` moves, interrupt-control instructions, and the whole 2.0 extended group (`0xff80` prefix).

## How to test
```
GHIDRA_INSTALL_DIR=<Ghidra with this directory linked in Ghidra/Processors/unSP> test/run-tests.sh [--real] <workdir>
```
Needs MAME's `unidasm` on PATH (black box), python3, a JDK. `--real` also fetches and builds naken_asm (pinned
commit + SHA-256), reproduces the emulator cases from their assembler source, runs the assembler round trip and
imports the assembled programs. The SLEIGH is generated: edit `tools/gen_unsp.py`; the suite checks the checked-in
file is its output.

## Results
| Area | Result |
|---|---|
| Build | `sleigh -l` clean (no pattern conflicts) on Ghidra 12.1.3, 12.1.4 and 12.2; `.sla` 90 KB; extension zips built for all three with `tools/build-module.sh --standard`. |
| Decode vs MAME unidasm `unsp20` | 131072 records (every 16-bit first word x 2 second words; 67657 distinct byte strings): 97420 agree exactly (after number normalisation), 33646 invalid in both, 4 blank words (`0x0000`, `0xffff`, which unidasm prints as `--`), 2 `0xff80` records (explained below), **0 unexplained**. |
| Extended group vs `unsp20` | prefix `0xff80` x every second word x 2 third words: 131072 records, 76288 agree, 54784 are `0xff80` followed by a word the oracle calls invalid (decoded as the v1.x multiply-accumulate, explained below), **0 differences**. |
| Older versions | `unsp12`: 96908 agree, 512 instructions of the newer version, **0 differences**. `unsp10`: 88252 agree, 8464 newer-version instructions, 704 encodings reassigned in 1.2 (`0xf020..0xf038` are multiplies in 1.0, `ds`/`fr` moves from 1.2), **0 differences**. |
| Every constructor reached | 914/914 (both SECBANK states, main and extended corpora). |
| Assembler round trip | 219 addressing-mode forms written in naken_asm syntax, assembled, decoded by Ghidra: 0 differ (1 further form is not accepted by naken_asm). |
| Semantics | 133 hand-computed emulator cases in Ghidra's `EmulatorHelper` (ALU results and every flag, carry chains, all addressing modes, DS wrap, SB shifts, all 14 conditions x 5 flag states, call/retf/reti/break, push/pop, multiply, inner product with the FIR data move, bit ops, ds/fr moves, SECBANK, the extended group). One deliberately wrong expectation is detected. |
| Real code | no freely licensed compiled u'nSP binary was found (see Unverified); the assembled test programs (`test/real/progs.asm`: memcpy, checksum with carry chain, array maximum, string length, a jump-table dispatch, a dot product) import, analyse and decompile: 84 instructions, 7 functions, 0 error/warning bookmarks, 7/7 decompile, the switch is recovered; Ghidra's listing equals unidasm's at all 84 addresses. |

Explanations of the non-agreeing classes: MAME prints `--` for the blank words; `0xff80` alone is the v1.x
`MR = [pc]*[sp], ss, 16` in `unsp10/12` and the extended-group prefix in 2.0 (a hybrid language has to pick;
nothing uses the first meaning), so `0xff80` followed by an invalid extended word decodes as that multiply.

## Semantics: where the p-code comes from
ALU flags, branches, stack, call/retf, multiply, FIR data move: the ISC-licensed veesem emulator
(`cpu.cc`, commit 42fb8f0) and the vsmile-hardware-docs notes. Encodings: MAME unidasm used as a black box (never
read). Checked by the 133 emulator cases (expectations computed by hand from those notes, not from this module).

## Doesn't work
* `divs`, `divq`, `exp` and the register-count shifts `asr/asror/lsl/lslor/lsr/lsror/rol/ror Rd, Rs` are pcodeops
  (`divs_op`...): no documentation of their semantics is available (the Programmer's Guide is only inside the
  vendor IDE).
* Entering an interrupt (pushing PC/SR, loading the vector, setting the mode) is hardware behaviour. `in_irq` /
  `in_fiq` are never set by the module; `reti` clears them.
* `sb` is one register; the hardware has one per interrupt mode. Banking it would put the mode bits into every
  shift's p-code and make shifts unreadable in the decompiler.
* `fraction on` (fixed-point multiplies) and `fr` bit positions are not modelled (undocumented here); `fr` is a plain
  16-bit register, the mode instructions set separate flag registers.
* Writing the CS bits of SR does not redirect a later `pc = ...` jump (CS comes from the instruction address).
* `pc` used as a pointer register with auto-increment (`[pc++]`) reads the address but does not move PC.
* Decompiler: pushes show as `*(undefined2 *)ZEXT23(&stack0x0000) = ...` and the `call` of a function pushes
  PC and SR visibly. Ghidra's stack model is byte based, the u'nSP stack pointer is a 16-bit word address in a
  22-bit word-addressed space; no cspec setting maps one onto the other.
* Calling convention (`unsp.cspec`) is the original's, unchanged and unverified (the unSP GCC ABI is documented
  in the Programming Tools manual only).

## Unverified
* Polarity of `tstb` (Z set when the tested bit is clear, as in the original) and bit-index masking for register
  bit numbers (`& 0xf`): no documentation or oracle.
* Everything the v1.3 documentation would settle (SS/MDS registers, which are declared but not used).
* Hardware behaviour of the encodings the three MAME decoders call invalid.
* Real code: no freely licensed compiled binary. The V.Smile BIOS/cartridges are commercial; sp1187/vsmile-demos,
  bmx/vsmilestuff and sgadrat/vsmile_demo_dragon carry no license; vsmile-dev/unsp-gcc is GPL-2 but its tree has no
  `configure` target for unsp (the compiler cannot be built without work), and the assembler it needs is not in
  the repository. Tested with assembled programs instead (naken_asm).

## Reference-tool findings (MAME unidasm, naken_asm)
* unidasm prints `--` for `0x0000` and `0xffff` (blank memory) although both are valid encodings.
* unidasm `unsp20`: the extended-group invalid forms are reported per group (`<INVALID Ra = Ra op Rb form>`...),
  which made the enumeration of valid extended words possible.
* naken_asm does not accept `mac.ss [r2],[r3],4` (only some pointer register pairs); it writes pc-relative jumps as
  absolute addresses and rejects some valid forms. No encoding bug was found in anything it accepted.
