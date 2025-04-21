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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The result of a 
 * {@link Loader#load(ghidra.app.util.bin.ByteProvider, String, Project, String, LoadSpec, List, MessageLog, Object, TaskMonitor) load}.
 * A {@link LoadResults} object provides convenient access to and operations on the underlying 
 * {@link Loaded} {@link DomainObject}s that got loaded.
 * 
 * @param <T> The type of {@link DomainObject}s that were loaded
 */
public class LoadResults<T extends DomainObject> implements Iterable<Loaded<T>>, AutoCloseable {

	private final List<Loaded<T>> loadedList;

	/**
	 * Creates a new {@link LoadResults} that contains the given non-empty {@link List} of 
	 * {@link Loaded} {@link DomainObject}s.  The first entry in the {@link List} is assumed to be
	 * the {@link #getPrimary() primary} {@link Loaded} {@link DomainObject}.
	 * 
	 * @param loadedList A {@link List} of {@link Loaded} {@link DomainObject}s
	 * @throws IllegalArgumentException if the provided {@link List} is null or empty
	 */
	public LoadResults(List<Loaded<T>> loadedList) throws IllegalArgumentException {
		if (loadedList == null || loadedList.isEmpty()) {
			throw new IllegalArgumentException("The loaded list must not be empty");
		}
		this.loadedList = new ArrayList<>(loadedList);
	}
	
	/**
	 * Creates a new {@link LoadResults} that contains a new {@link Loaded} 
	 * {@link DomainObject} created from the given parameters.  This new {@link Loaded} 
	 * {@link DomainObject} is assumed to be the {@link #getPrimary() primary} {@link Loaded} 
	 * {@link DomainObject}.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a 
	 *   {@link #save(TaskMonitor) save} occurs, this will attempted to be used for the resulting 
	 *   {@link DomainFile}'s name.
	 * @param project If not null, the project this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor) save} operation.  If null or empty, the root project folder will
	 *   be used.
	 * @param consumer The consumer of the {@code domainObject}, which will get used when this 
	 *   object is {@link #close() closed}. Wrapping a {@link DomainObject} in a {@link Loaded} 
	 *   transfers responsibility of releasing the {@link DomainObject} to this 
	 *   {@link LoadResults}'s {@link #close()} method.
	 */
	public LoadResults(T domainObject, String name, Project project, String projectFolderPath,
			Object consumer) {
		this(List.of(new Loaded<T>(domainObject, name, project, projectFolderPath, consumer)));
	}

	/**
	 * Gets the "primary" {@link Loaded} {@link DomainObject}, who's meaning is defined by each 
	 * {@link Loader} implementation
	 * 
	 * @return The "primary" {@link Loaded} {@link DomainObject}
	 */
	public Loaded<T> getPrimary() {
		return loadedList.getFirst();
	}

	/**
	 * Removes the "primary" {@link Loaded} {@link DomainObject} from this {@link LoadResults}.
	 * <p>
	 * NOTE: It is the responsibility of the caller to {@link Loaded#close()} the returned 
	 * {@link Loaded} {@link DomainObject} when finished with it. 
	 * 
	 * @return The removed "primary" {@link Loaded} {@link DomainObject}
	 */
	public Loaded<T> removePrimary() {
		return loadedList.removeFirst();
	}

	/**
	 * Gets the "primary" {@link DomainObject}, whose meaning is defined by each {@link Loader} 
	 * implementation
	 * 
	 * @param consumer The consumer of the returned {@link DomainObject}
	 * @return The "primary" {@link DomainObject}
	 */
	public T getPrimaryDomainObject(Object consumer) {
		return loadedList.getFirst().getDomainObject(consumer);
	}

	/**
	 * Gets the {@link DomainObject}s, whose meaning is defined by each {@link Loader} 
	 * implementation
	 * 
	 * @param consumer The consumer of the returned {@link DomainObject}s
	 * @return The {@link DomainObject}s
	 */
	public List<T> getDomainObjects(Object consumer) {
		return loadedList.stream().map(e -> e.getDomainObject(consumer)).toList();
	}

	/**
	 * Gets the number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}.  The
	 * size will always be greater than 0.
	 * 
	 * @return The number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}
	 */
	public int size() {
		return loadedList.size();
	}

	/**
	 * {@link Loaded#save(TaskMonitor) Saves} each {@link Loaded} {@link DomainObject} to the given 
	 * {@link Project}.
	 * <p>
	 * NOTE: If any fail to save, none will be saved (already saved {@link DomainFile}s will be
	 * cleaned up/deleted), and all {@link Loaded} {@link DomainObject}s will have been
	 * {@link #close() closed}.
	 * 
	 * @param monitor A cancelable task monitor
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException If there was a problem saving
	 * @see Loaded#save(TaskMonitor)
	 */
	public void save(TaskMonitor monitor)
			throws CancelledException, IOException {
		boolean success = false;
		try {
			for (Loaded<T> loaded : loadedList) {
				loaded.save(monitor);
			}
			success = true;
		}
		finally {
			if (!success) {
				for (Loaded<T> loaded : this) {
					try {
						loaded.closeAndDelete();
					}
					catch (Exception e1) {
						Msg.error(getClass(), "Failed to delete: " + loaded);
					}
				}
			}
		}
	}

	@Override
	public Iterator<Loaded<T>> iterator() {
		return loadedList.iterator();
	}

	@Override
	public void close() {
		loadedList.forEach(Loaded::close);
	}
}
