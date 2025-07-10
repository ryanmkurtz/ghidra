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

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.model.ProjectLocator;

public class LoaderUtils {

	/**
	 * Joins the given path elements to form a suitable project path. Empty and null path elements
	 * are ignored. The returned path's separators are converted to unix-style and
	 * {@link ProjectLocator#DISALLOWED_CHARS disallowed project characters} are stripped out.
	 * 
	 * @param pathElements The path elements to join
	 * @return A single project path consisting of the given path elements appended together
	 * @see FSUtilities#appendPath(String...)
	 */
	public static String createProjectPath(String... pathElements) {
		String str = FSUtilities.appendPath(pathElements);
		if (str == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < str.length(); i++) {
			char ch = str.charAt(i);
			if (!ProjectLocator.DISALLOWED_CHARS.contains(ch)) {
				sb.append(ch);
			}
		}
		return sb.toString();
	}
}
