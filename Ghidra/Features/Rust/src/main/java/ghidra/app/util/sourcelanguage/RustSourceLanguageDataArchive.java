package ghidra.app.util.sourcelanguage;

import java.util.List;

import ghidra.program.model.listing.Program;

public class RustSourceLanguageDataArchive implements SourceLanguageDataArchive {

	@Override
	public String getCompatibleSourceLanguage() {
		return RustSourceLanguageUtils.RUST_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public List<String> getDataArchives(Program program) {
		return List.of("rust-common");
	}
}
