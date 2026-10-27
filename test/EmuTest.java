// P-code semantics check for the u'nSP module.  Reads test/emu/cases.txt (expectations worked out by hand
// from the u'nSP ISA notes, see the file header), writes the code at word address 0x800, sets registers
// and memory, emulates with Ghidra's EmulatorHelper until the PC reaches the end of the code (or the
// address given by "until"), and compares registers and memory.
//
// Case format (one directive per line, '#' comments):
//   case <name> [broken]      "broken" cases carry a deliberately wrong expectation
//   code <hex>                bytes placed at word address 0x800 (the byte string of the image)
//   at <hex-word-address>     start address instead of 0x800 (code is written there)
//   until <hex-word-address>  stop when the PC reaches this address (default: end of code)
//   set <reg> <value>         register (sp r1 r2 r3 r4 bp sr pc fr sb ...) or ram:<word-address>
//   expect <reg> <value>      register, or ram:<word-address> (16 bit word), or PC (word address)
//   end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class EmuTest extends GhidraScript {

	private static class Case {
		String name;
		boolean broken;
		byte[] code;
		long start = 0x800;
		long until = -1;
		Map<String, Long> set = new LinkedHashMap<>();
		Map<String, Long> expect = new LinkedHashMap<>();
	}

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0) {
					line = line.substring(0, h);
				}
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						for (int i = 2; i < f.length; i++) {
							if (f[i].equals("broken")) {
								c.broken = true;
							}
						}
						break;
					case "code":
						String hex = String.join("", java.util.Arrays.copyOfRange(f, 1, f.length));
						c.code = new byte[hex.length() / 2];
						for (int i = 0; i < c.code.length; i++) {
							c.code[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
						}
						break;
					case "at":
						c.start = Long.parseLong(f[1], 16);
						break;
					case "until":
						c.until = Long.parseLong(f[1], 16);
						break;
					case "set":
						c.set.put(f[1], Long.decode(f[2]));
						break;
					case "expect":
						c.expect.put(f[1], Long.decode(f[2]));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	// word address -> Address of the (word addressable) default space
	private Address wa(long word) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddressInThisSpaceOnly(
			word * 2);
	}

	private boolean isMem(String key) {
		return key.startsWith("ram:");
	}

	private Address memAddr(String key) {
		return wa(Long.parseLong(key.substring(4), 16));
	}

	private String runCase(Case c) throws Exception {
		Address start = wa(c.start);
		Address end = wa(c.until >= 0 ? c.until : c.start + c.code.length / 2);
		clearListing(new AddressSet(start, start.add(c.code.length + 16)));
		setBytes(start, c.code);
		// disassemble first so that context changes (SECBANK) propagate through the code
		disassemble(start);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (Map.Entry<String, Long> e : c.set.entrySet()) {
				if (isMem(e.getKey())) {
					long v = e.getValue();
					emu.writeMemory(memAddr(e.getKey()),
						new byte[] { (byte) (v & 0xff), (byte) ((v >> 8) & 0xff) });
				}
				else {
					emu.writeRegister(e.getKey(), e.getValue());
				}
			}
			emu.writeRegister(emu.getPCRegister(), c.start);
			int steps = 0;
			while (emu.getExecutionAddress().getAddressableWordOffset() != end.getAddressableWordOffset()) {
				if (++steps > 4000) {
					return "did not reach the end (pc " + emu.getExecutionAddress() + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + emu.getExecutionAddress() + ": " +
						emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, Long> e : c.expect.entrySet()) {
				long got;
				if (isMem(e.getKey())) {
					byte[] b = emu.readMemory(memAddr(e.getKey()), 2);
					got = (b[0] & 0xff) | ((b[1] & 0xff) << 8);
				}
				else if (e.getKey().equals("PC")) {
					got = emu.getExecutionAddress().getAddressableWordOffset();
				}
				else {
					got = emu.readRegister(e.getKey()).longValue();
				}
				if (got != e.getValue()) {
					bad.append(String.format(" %s=0x%x (expected 0x%x)", e.getKey(), got,
						e.getValue()));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		String lang = currentProgram.getLanguageID().getIdAsString();
		int pass = 0, fail = 0, brokenSeen = 0, brokenMissed = 0;
		for (Case c : cases) {
			String err = runCase(c);
			if (c.broken) {
				if (err != null) {
					brokenSeen++;
					out.println("PASS (broken expectation detected) " + c.name + ": " + err);
				}
				else {
					brokenMissed++;
					out.println("FAIL " + c.name + ": the deliberately wrong expectation passed");
				}
			}
			else if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed, broken expectation %s%n", lang, pass,
			fail + brokenMissed, brokenSeen > 0 && brokenMissed == 0 ? "detected" : "NOT detected");
		out.close();
	}
}
