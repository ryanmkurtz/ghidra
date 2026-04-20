package ghidra.app.util.sourcelanguage;

import java.util.Arrays;

import ghidra.app.util.bin.format.objc.objc2.Objc2Constants;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class MachoObjcSourceLanguage implements SourceLanguage {

	@Override
	public String getName() {
		return ObjcSourceLanguageUtils.OBJC_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public String getFormatName() {
		return MachoLoader.MACH_O_NAME;
	}

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor) {
		if (!program.getExecutableFormat().equals(getFormatName())) {
			return false;
		}
		return Arrays.stream(program.getMemory().getBlocks())
				.map(MemoryBlock::getName)
				.anyMatch(n -> n.startsWith(Objc2Constants.OBJC2_PREFIX));
	}
}
