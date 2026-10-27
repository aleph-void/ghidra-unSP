// Pre-analysis script: disassemble and create a function at each given word address (hex).
// Script args: <hex-word-address> ...
//@category Testing

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SeedEntries extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (String a : getScriptArgs()) {
			Address ad = currentProgram.getAddressFactory().getDefaultAddressSpace()
					.getAddressInThisSpaceOnly(Long.parseLong(a, 16) * 2);
			disassemble(ad);
			createFunction(ad, null);
		}
	}
}
