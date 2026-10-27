# SunPlus µnSP module for Ghidra

A Ghidra module for disassembling/decompiling µnSP binaries. (Original description: "Incomplete and under
development.") Covers the Sunplus / Generalplus SPG2xx and GPL16xxx chips (the V.Smile family and other toys). Originally written by Samuel Anderson (credit to GMMan); this fork was
reworked and verified for [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare). The original text of this
README is kept below; sections that were out of date are corrected in place, and every item of the original
TODO list is marked fixed or remaining.

**Verification notes, results and reference-tool findings: [GHIDRA-RARE.md](GHIDRA-RARE.md). Credits and
the list of changes: [CREDITS.md](CREDITS.md). Prebuilt zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this
fork's Releases page.**

## Status
The SLEIGH specification was originally made without access to any official documentation, so it is some
hybrid of all of the various versions (1.0, 1.1, 1.2, 1.3, 2.0): one language, `unsp:LE:16:default`, decodes
the union of the instruction sets. It is now generated from tables (`tools/gen_unsp.py`; edit the generator,
not `unsp.slaspec`) and checked against an independent disassembler (MAME `unidasm`, all three versions) and an
independent assembler (naken_asm): see GHIDRA_RARE.md. The extended register set of the 2.0 ISA (`r8`-`r15`,
the `0xff80` prefix) is implemented. Decompiler output is usable; stack traffic is still shown as raw memory
accesses (see below).

Differences between the versions (found with the three MAME disassemblers; the module accepts all of them):
* 1.0 -> 1.2: bit operations (`tstb/setb/clrb/invb`), `MR = ..., uu`, multiply-accumulate with `uu`,
  register-count shifts (`asr/lsl/lsr/rol/ror/asror/lslor/lsror`), `R = ds`, `ds = R`, `R = fr`, `fr = R`,
  `fraction`, `secbank`, `irqnest`, `call mr`, `divs`, `divq`, `exp`. In 1.0 the words `0xf020..0xf038` are
  multiplies; they are the `ds`/`fr` moves from 1.2 on.
* 1.2 -> 2.0: `tstb/setb/clrb/invb` on `[imm16]` / `ds:[imm16]`, and the extended group introduced by `0xff80`.
  (In 1.x `0xff80` is `MR = [pc]*[sp], ss, 16`, which nothing uses; this module decodes it as the prefix.)

### TODO (original list) and what happened to it
- Eliminate unimpl: **fixed** (`break` is implemented). Remaining pcodeops, because no documentation of their
  semantics is available: `divs`, `divq`, `exp`, and the eight register-count shifts (`asr_op`...).
- Update cs correctly: **fixed** for control flow and for every read of SR: the code segment is derived from the
  instruction's own address (`inst_start`), `call`/`goto`/`retf`/`reti`/`break` take or restore the full 22-bit
  address. Remaining: a write to the CS bits of SR does not redirect a later `pc = ...` jump (the jump stays
  in the segment of the instruction).
- Cleanup decompiler output: **partly**. Pointer arithmetic is explicit instead of an opaque `segment`
  pcodeop, flags are bit ranges of SR, and jump tables (`pc = [r1]`) are recovered as `switch`. Remaining:
  pushes (`call` saves PC and SR) show up as `*(undefined2 *)ZEXT23(&stack0x0000) = ...`, because Ghidra's
  stack model cannot map a 16 bit word-addressed stack pointer onto its byte-based stack space.
- Find a way to handle far pointers in the decompiler: **remaining** (decompiler limit); `ds:[...]` accesses
  now compute the 22-bit address `(DS << 16) | offset` explicitly.
- Get the decompiler to recognize switch statements with jump tables: **works** (tested on an assembled
  dispatch routine, `test/real/progs.asm`).
- Implement push/pop fully: **fixed** (every register range, every pointer register, `retf`, `reti`, and the
  extended `r8`-`r15` push/pop).
- Revisit interrupts and related instructions: **fixed** to the extent the hardware is documented
  (`int/irq/fiq/fir_mov/fraction/secbank/irqnest` set their state bits, `break` takes the BREAK vector,
  `reti` leaves FIQ/IRQ mode). `secbank on/off` switch `r1`-`r4` to `sr1`-`sr4` (tracked as a context bit that
  follows the code). Remaining: entering an interrupt is hardware behaviour and is not modelled.
- Revisit multiplication: **fixed** (`MR = Rd*Rs` in `uu/us/ss`, multiply-accumulate with the FIR data move).
  Remaining: the effect of `fraction on` on the product is not documented and not modelled.
- Fix display for some instructions: **fixed** (display now follows the vendor-style text of MAME's disassembler).
- Investigate differences between 1.0, 1.1, 1.2, and 2.0: **done**, see above.

Other fixes found by testing are listed in CREDITS.md (for example `fir_mov on/off` were inverted, the carry
of `sub`/`cmp` was wrong when the subtrahend is zero, instructions with `PC` as destination wrote the register
without branching, `pop`/`push` were stubs).

## Build
Release zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on the Releases page of this fork. To build yourself,
either use the GhidraDev plugin for Eclipse, or
```
GHIDRA_INSTALL_DIR=path/to/ghidra ./gradlew buildExtension      # Ghidra 12: use $GHIDRA_INSTALL_DIR/support/gradle/gradlew
```
and install the zip from `dist/` with File > Install Extensions. The `.sla` is built by Ghidra when the
module is loaded (it is not checked in). `test/run-tests.sh` runs the verification suite.
