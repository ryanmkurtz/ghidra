/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.FileNotFoundException;
import java.io.IOException;

import ghidra.framework.model.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A loaded {@link DomainObject} produced by a {@link Loader}.  In addition to storing the loaded
 * {@link DomainObject}, it also stores the {@link Loader}'s desired name and project folder path 
 * for the loaded {@link DomainObject}, should it get saved to a project.
 * <p>
 * NOTE: If an object of this type is marked as {@link #setDiscard(boolean) discardable}, it should
 * be {@link #close() closed} and not saved. 
 * 
 * @param <T> The type of {@link DomainObject} that was loaded
 */
public class Loaded<T extends DomainObject> implements AutoCloseable {

	private final T domainObject;
	private final String name;
	private Project project;
	private String projectFolderPath;
	private Object consumer;

	private DomainFile domainFile;
	private boolean ignoreSave;
	private boolean discard;

	/**
	 * Creates a new {@link Loaded} object
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a {@link #save(TaskMonitor)} 
	 *   occurs, this will attempted to be used for the resulting {@link DomainFile}'s name.
	 * @param project If not null, the project this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation.  If null or empty, the root project folder will be 
	 *   used.
	 * @param consumer The consumer of the {@code domainObject}, which will get used when this 
	 *   object is {@link #close() closed}. Wrapping a {@link DomainObject} in a {@link Loaded} 
	 *   transfers responsibility of releasing the {@link DomainObject} to this {@link Loaded}'s 
	 *   {@link #close()} method.
	 */
	public Loaded(T domainObject, String name, Project project, String projectFolderPath,
			Object consumer) {
		this.domainObject = domainObject;
		this.name = name;
		this.project = project;
		this.consumer = consumer;
		setProjectFolderPath(projectFolderPath);
	}

	/**
	 * Creates a {@link Loaded} view on an existing {@link DomainFile}. This type of {@link Loaded}
	 * object cannot be saved.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param domainFile The {@link DomainFile} to be loaded
	 * @param consumer The consumer of the {@code domainObject}, which will get used when this object is
	 *   {@link #close() closed}. Wrapping a {@link DomainObject} in a {@link Loaded} transfers
	 *   responsibility of releasing the {@link DomainObject} to this {@link Loaded}'s 
	 *   {@link #close()} method.
	 */
	public Loaded(T domainObject, DomainFile domainFile, Object consumer) {
		this(domainObject, domainFile.getName(), null, domainFile.getParent().getPathname(),
			consumer);
		this.domainFile = domainFile;
		this.ignoreSave = true;
	}

	/**
	 * Gets the loaded {@link DomainObject}.
	 * <p>
	 * NOTE: Calling this method "consumes" the {@link DomainObject}. It is the responsibility of
	 * the caller to properly {@link DomainObject#release(Object) release} it when done. This
	 * {@link DomainObject#release(Object)} does not replace the requirement to 
	 * {@link #close()} the {@link Loaded} object when done.
	 * 
	 * @param con The consumer of the returned {@link DomainObject}
	 * @return The loaded {@link DomainObject}
	 */
	public T getDomainObject(Object con) {
		domainObject.addConsumer(con);
		return domainObject;
	}

	/**
	 * Gets the loaded {@link DomainObject}'s type
	 * 
	 * @return the loaded {@link DomainObject}'s type
	 */
	public Class<? extends DomainObject> getDomainObjectType() {
		return domainObject.getClass();
	}

	/**
	 * Gets the name of the loaded {@link DomainObject}.  If a {@link #save(TaskMonitor)} occurs, 
	 * this will attempted to be used for the resulting {@link DomainFile}'s name.
	 * 
	 * @return the name of the loaded {@link DomainObject}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the {@link Project} this will get saved to during a {@link #save(TaskMonitor)} operation
	 *
	 *@return The {@link Project} this will get saved to during a {@link #save(TaskMonitor)} 
	 *  operation (could be null)
	 */
	public Project getProject() {
		return project;
	}

	/**
	 * Gets the project folder path this will get saved to during a {@link #save(TaskMonitor)} 
	 * operation.
	 * <p>
	 * NOTE: The returned path will always end with a "/".
	 * 
	 * @return the project folder path
	 */
	public String getProjectFolderPath() {
		return projectFolderPath;
	}

	/**
	 * Sets the project folder path this will get saved to during a {@link #save(TaskMonitor)} 
	 * operation.
	 * 
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation.  If null or empty, the root project folder will be 
	 *   used.
	 */
	public void setProjectFolderPath(String projectFolderPath) {
		if (projectFolderPath == null || projectFolderPath.isBlank()) {
			projectFolderPath = "/";
		}
		else if (!projectFolderPath.endsWith("/")) {
			projectFolderPath += "/";
		}
		this.projectFolderPath = projectFolderPath;
	}

	/**
	 * Saves the loaded {@link DomainObject} to the given {@link Project} at this object's 
	 * project folder path, using this object's name.
	 * <p>
	 * If a {@link DomainFile} already exists with the same desired name and project folder path,
	 * the desired name will get a counter value appended to it to avoid a naming conflict.
	 * Therefore, it should not be assumed that the returned {@link DomainFile} will have the same
	 * name as a call to {@link #getName()}.
	 * 
	 * @param monitor A cancelable task monitor
	 * @return The {@link DomainFile} where the save happened
	 * @throws CancelledException if the operation was cancelled
	 * @throws ClosedException if the loaded {@link DomainObject} was already closed
	 * @throws IOException If there was an IO-related error, an invalid name was specified, or it
	 *   was already successfully saved and still exists
	 */
	public DomainFile save(TaskMonitor monitor)
			throws CancelledException, ClosedException, IOException {

		if (ignoreSave) {
			return domainFile;
		}

		if (domainObject.isClosed()) {
			throw new ClosedException(
				"Cannot saved closed DomainObject: " + domainObject.getName());
		}

		try {
			if (getSavedDomainFile() != null) { // 
				throw new IOException("Already saved to " + domainFile);
			}
		}
		catch (FileNotFoundException e) {
			// DomainFile was already saved, but no longer exists.
			// Allow the save to proceed.
			domainFile = null;
		}

		int uniqueNameIndex = 0;
		String uniqueName = name;
		try {
			DomainFolder programFolder = ProjectDataUtils.createDomainFolderPath(
				project.getProjectData().getRootFolder(), projectFolderPath);
			while (!monitor.isCancelled()) {
				try {
					domainFile = programFolder.createFile(uniqueName, domainObject, monitor);
					return domainFile;
				}
				catch (DuplicateFileException e) {
					uniqueName = name + "." + uniqueNameIndex;
					++uniqueNameIndex;
				}
			}
		}
		catch (InvalidNameException e) {
			throw new IOException(e);
		}
		throw new CancelledException();
	}

	/**
	 * Gets the loaded {@link DomainObject}'s associated {@link DomainFile} that was
	 * {@link #save(TaskMonitor) saved}
	 * 
	 * @return The loaded {@link DomainObject}'s associated saved {@link DomainFile}, or null if 
	 *   was not saved
	 * @throws FileNotFoundException If the loaded {@link DomainObject} was saved but the associated
	 *   {@link DomainFile} no longer exists
	 * @see #save(TaskMonitor)
	 */
	public DomainFile getSavedDomainFile() throws FileNotFoundException {
		if (domainFile != null && !domainFile.exists()) {
			throw new FileNotFoundException("Saved DomainFile no longer exists: " + domainFile);
		}
		return domainFile;
	}

	/**
	 * Checks to see if this {@link Loaded} {@link DomainObject} should be discarded (not saved)
	 * 
	 * @return True if this {@link Loaded} {@link DomainObject} should be discarded; otherwise, 
	 *   false
	 */
	public boolean shouldDiscard() {
		return discard;
	}

	/**
	 * Sets whether or not this {@link Loaded} {@link DomainObject} should be discarded (not saved)
	 * 
	 * @param discard True if this {@link Loaded} {@link DomainObject} should be discarded;
	 *   otherwise, false
	 */
	public void setDiscard(boolean discard) {
		this.discard = discard;
	}


	/**
	 * {@link #close() Closes} this {@link Loaded} and deletes the loaded {@link DomainObject}'s 
	 * associated {@link DomainFile} that was {@link #save(TaskMonitor) saved}.  This method has no 
	 * effect if it was never saved.
	 * 
	 * @throws IOException If there was an issue deleting the saved {@link DomainFile}
	 * @see #save(TaskMonitor)
	 */
	void closeAndDelete() throws IOException {
		close();
		if (domainFile != null && domainFile.exists()) {
			domainFile.delete();
			domainFile = null;
		}
	}

	@Override
	public void close() {
		if (consumer != null && !domainObject.isClosed() && domainObject.isUsedBy(consumer)) {
			domainObject.release(consumer);
		}
	}

	@Override
	public String toString() {
		return getProjectFolderPath() + getName();
	}
}
