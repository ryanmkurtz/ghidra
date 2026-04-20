package ghidra.app.util.sourcelanguage;

import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

public class ObjcSourceLanguageSpecExtension implements SourceLanguageSpecExtension {

	@Override
	public String getCompatibleSourceLanguage() {
		return ObjcSourceLanguageUtils.OBJC_SOURCE_LANGUAGE_NAME;
	}

	@Override
	public ResourceFile getSpecExtensionConfig() throws FileNotFoundException {
		return Application.getModuleDataFile("extensions.json");
	}
}
