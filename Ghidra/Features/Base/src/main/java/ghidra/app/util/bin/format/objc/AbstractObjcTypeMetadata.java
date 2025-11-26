package ghidra.app.util.bin.format.objc;

import java.io.Closeable;
import java.io.IOException;

import ghidra.app.util.bin.format.objc.objc1.Objc1TypeMetadata;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractObjcTypeMetadata implements Closeable {

	protected Program program;
	protected TaskMonitor monitor;
	protected MessageLog log;
	protected ObjcState state;

	/**
	 * Creates a new {@link AbstractObjcTypeMetadata}
	 * 
	 * @param state The {@link ObjcState state}
	 * @param program The {@link Program}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public AbstractObjcTypeMetadata(ObjcState state, Program program, TaskMonitor monitor,
			MessageLog log) throws IOException, CancelledException {
		this.state = state;
		this.program = program;
		this.monitor = monitor;
		this.log = log;
	}

	/**
	 * Applies the type metadata to the program
	 */
	public abstract void applyTo();

	/**
	 * Convenience method to perform logging
	 * 
	 * @param message The message to log
	 */
	public void log(String message) {
		log.appendMsg(Objc1TypeMetadata.class.getSimpleName(), message);
	}

	@Override
	public void close() {
		state.close();
	}
}
