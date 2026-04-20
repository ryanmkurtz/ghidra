package ghidra.app.util.sourcelanguage;

import java.io.IOException;

import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MachoRustSourceLanguage implements SourceLanguage {

	@Override
	public String getName() {
		return RustSourceLanguageUtils.RUST_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public String getFormatName() {
		return MachoLoader.MACH_O_NAME;
	}

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!program.getExecutableFormat().equals(getFormatName())) {
			return false;
		}
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(SectionNames.TEXT_CONST) &&
				block.getComment().equals(SegmentNames.SEG_TEXT) &&
				RustSourceLanguageUtils.isRust(program, block, monitor)) {
				return true;
			}
		}
		return false;
	}
}
