package ghidra.app.util.sourcelanguage;

import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.util.classfinder.ExtensionPoint;

public interface SourceLanguageSpecExtension extends ExtensionPoint {

	/**
	 * {@return the name of the source language this {@link SourceLanguageSpecExtension} is
	 * compatible with}
	 */
	public String getCompatibleSourceLanguage();

	/**
	 * {@return the source language's spec extension configuration file}
	 * 
	 * @throws FileNotFoundException if the file was not found
	 */
	public ResourceFile getSpecExtensionConfig() throws FileNotFoundException;
}
