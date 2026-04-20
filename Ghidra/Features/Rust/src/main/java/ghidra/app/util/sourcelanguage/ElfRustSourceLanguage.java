package ghidra.app.util.sourcelanguage;

import java.io.IOException;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.info.ElfComment;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ElfRustSourceLanguage implements SourceLanguage {

	private static final Pattern ELF_COMMENT_REGEX = Pattern.compile("^rustc version .*$");

	@Override
	public String getName() {
		return RustSourceLanguageUtils.RUST_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public String getFormatName() {
		return ElfLoader.ELF_NAME;
	}

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!program.getExecutableFormat().equals(getFormatName())) {
			return false;
		}

		// ELF binaries can contain a ".comment" section that records the toolchains that
		// produced the binary.  Search this first as its quick and easy. 
		ElfComment elfComments = ElfComment.fromProgram(program);
		if (elfComments != null) {
			for (String s : elfComments.getCommentStrings()) {
				if (ELF_COMMENT_REGEX.matcher(s).matches()) {
					return true;
				}
			}
		}

		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(ElfSectionHeaderConstants.dot_rodata) &&
				RustSourceLanguageUtils.isRust(program, block, monitor)) {
				return true;
			}
		}
		return false;
	}
}
