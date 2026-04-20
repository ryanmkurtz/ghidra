package ghidra.app.util.sourcelanguage;

import java.io.IOException;

import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PeRustSourceLanguage implements SourceLanguage {

	@Override
	public String getName() {
		return RustSourceLanguageUtils.RUST_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public String getFormatName() {
		return PeLoader.PE_NAME;
	}

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!program.getExecutableFormat().equals(getFormatName())) {
			return false;
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(".rdata") &&
				RustSourceLanguageUtils.isRust(program, block, monitor)) {
				return true;
			}
		}
		return false;
	}
}
