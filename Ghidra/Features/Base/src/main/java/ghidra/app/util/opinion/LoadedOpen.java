package ghidra.app.util.opinion;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;

/**
 * A loaded, open {@link DomainObject} that has already been saved to a {@link DomainFile}
 * 
 * @param <T> The type of open {@link DomainObject}
 */
public class LoadedOpen<T extends DomainObject> extends Loaded<T> {

	/**
	 * Creates a {@link Loaded} view on an existing {@link DomainFile}. This type of {@link Loaded}
	 * object cannot be re-saved.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param domainFile The {@link DomainFile} associated with the loaded {@link DomainObject}
	 * @param consumer A reference to the object "consuming" the returned {@link Loaded} 
	 *   {@link DomainObject}, used to ensure the underlying {@link DomainObject} is only closed 
	 *   when every consumer is done with it (see {@link #close()}). NOTE:  Wrapping a 
	 *   {@link DomainObject} in a {@link Loaded} transfers responsibility of releasing the 
	 *   given {@link DomainObject} to this {@link Loaded}'s {@link #close()} method. 
	 * @throws LoadException if the given {@link DomainFile} is not open
	 */
	public LoadedOpen(T domainObject, DomainFile domainFile, Object consumer) throws LoadException {
		super(domainObject, domainFile.getName(), null, domainFile.getParent().getPathname(),
			consumer);
		this.domainFile = domainFile;
		if (!domainFile.isOpen()) {
			throw new LoadException(domainFile + " is not open");
		}
	}

	@Override
	public DomainFile save(TaskMonitor monitor) {
		return domainFile;
	}

}
