package ghidra.app.util.sourcelanguage;

import java.util.List;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

public interface SourceLanguageDataArchive extends ExtensionPoint {

	/**
	 * {@return the name of the source language this {@link SourceLanguageDataArchive} is
	 * compatible with}
	 */
	public String getCompatibleSourceLanguage();

	/**
	 * {@return the data archives provided by the source language}
	 * 
	 * @param program The {@link Program}
	 */
	public List<String> getDataArchives(Program program);
}
