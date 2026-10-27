// Prints text and p-code of each hex case (one per line) placed at the address given as "@hex" (default 0x1000).
// Script args: <cases.txt> <outfile> [@addr]
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeDump extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		PrintStream out = new PrintStream(args[1]);
		Language lang = currentProgram.getLanguage();
		long base = 0x1000;
		if (args.length > 2 && args[2].startsWith("@")) {
			base = Long.parseLong(args[2].substring(1), 16);
		}
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base);
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}
				byte[] b = new byte[line.length() / 2 + 8];
				for (int i = 0; i < line.length() / 2; i++) {
					b[i] = (byte) Integer.parseInt(line.substring(2 * i, 2 * i + 2), 16);
				}
				ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
				MemBuffer buf = new ByteMemBufferImpl(a, b, true);
				InstructionPrototype proto = lang.parse(buf, ctx, false);
				PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
				out.printf("== %s  len=%d  %s%n", line, pi.getLength(), pi);
				for (PcodeOp op : pi.getPcode()) {
					out.println("   " + op);
				}
			}
		}
		out.close();
	}
}
