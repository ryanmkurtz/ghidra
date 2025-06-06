package ghidra.app.script;

import java.io.OutputStream;
import java.io.PrintWriter;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.services.ConsoleService;
import ghidra.util.task.TaskMonitor;

/**
 * Class to encapsulate {@link GhidraScript} control mechanisms such as stdout/stderr writers and
 * other feedback to the user
 */
public class ScriptControls {

	/**
	 * A {@link ScriptControls} that does nothing
	 */
	public static final ScriptControls NONE =
		new ScriptControls(null, null, false, TaskMonitor.DUMMY);

	private PrintWriter writer;
	private PrintWriter errorWriter;
	private boolean decorateOutput;
	private TaskMonitor monitor;

	/**
	 * Creates a new {@link ScriptControls}
	 * 
	 * @param writer The target of script "print" statements (may be null)
	 * @param errorWriter The target of script "printerr" statements (may be null)
	 * @param decorateOutput True to decorate the writer output with a script name prefix; 
	 *   otherwise, false (see {@link GhidraScript#decorate(String)}
	 * @param monitor A cancellable monitor
	 */
	public ScriptControls(PrintWriter writer, PrintWriter errorWriter, boolean decorateOutput,
			TaskMonitor monitor) {
		this.writer = writer;
		this.errorWriter = errorWriter;
		this.decorateOutput = decorateOutput;
		this.monitor = monitor;
	}

	/**
	 * Creates a new {@link ScriptControls} with no decorated output
	 * 
	 * @param writer The target of script "print" statements (may be null)
	 * @param errorWriter The target of script "printerr" statements (may be null)
	 *   otherwise, false (see {@link GhidraScript#decorate(String)}
	 * @param monitor A cancellable monitor
	 */
	public ScriptControls(PrintWriter writer, PrintWriter errorWriter, TaskMonitor monitor) {
		this(writer, errorWriter, false, monitor);
	}

	/**
	 * Creates a new {@link ScriptControls} with no decorated output
	 * 
	 * @param stream The target of script "print" statements (may be null)
	 * @param errorStream The target of script "printerr" statements (may be null)
	 *   otherwise, false (see {@link GhidraScript#decorate(String)}
	 * @param monitor A cancellable monitor
	 */
	public ScriptControls(OutputStream stream, OutputStream errorStream, TaskMonitor monitor) {
		this(new PrintWriter(stream, true), new PrintWriter(errorStream, true), false, monitor);
	}

	/**
	 * Creates a new {@link ScriptControls} with no decorated output
	 * 
	 * @param console The target of script "print" and "printerr" statements
	 * @param monitor A cancellable monitor
	 */
	public ScriptControls(ConsoleService console, TaskMonitor monitor) {
		this(console.getStdOut(), console.getStdErr(), monitor);
	}

	/**
	 * Creates a new {@link ScriptControls} with no decorated output
	 * 
	 * @param console The target of script "print" and "printerr" statements
	 * @param monitor A cancellable monitor
	 */
	public ScriptControls(InterpreterConsole console, TaskMonitor monitor) {
		this(console.getStdOut(), console.getStdErr(), monitor);
	}

	/**
	 * {@return the target of script "print" statements (may be null)}
	 */
	public PrintWriter getWriter() {
		return writer;
	}

	/**
	 * {@return the target of script "printerr" statements (may be null)}
	 */
	public PrintWriter getErrorWriter() {
		return errorWriter;
	}

	/**
	 * {@return True to decorate the writer output with a script name prefix; otherwise, false}
	 * 
	 * @see GhidraScript#decorate(String)
	 */
	public boolean shouldDecorateOutput() {
		return decorateOutput;
	}

	/**
	 * {@return A cancellable monitor}
	 */
	public TaskMonitor getMonitor() {
		return monitor;
	}

}
