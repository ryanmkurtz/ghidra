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
