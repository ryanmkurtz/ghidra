package ghidra.app.util.sourcelanguage;

import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class RustSourceLanguageSpecExtension implements SourceLanguageSpecExtension {

	@Override
	public String getCompatibleSourceLanguage() {
		return RustSourceLanguageUtils.RUST_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public ResourceFile getSpecExtensionConfig() throws FileNotFoundException {
		return Application.getModuleDataFile("extensions.json");
	}
}
