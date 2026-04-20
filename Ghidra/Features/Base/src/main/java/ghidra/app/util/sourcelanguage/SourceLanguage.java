package ghidra.app.util.sourcelanguage;

import java.io.IOException;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link ExtensionPoint} to dynamically support source language-specific features
 */
public interface SourceLanguage extends ExtensionPoint {

	/**
	 * {@return the name of the source language}
	 */
	public String getName();

	/**
	 * {@return the name of the binary file format}
	 */
	public String getFormatName();

	/**
	 * {@return true if the source language exists in the given {@link Program}; otherwise false}
	 * 
	 * @param program The {@link Program}
	 * @param monitor The {@link TaskMonitor}
	 * @throws IOException if an IO-related error occurred
	 * @throws CancelledException if the user cancelled the operation
	 */
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException;
}
