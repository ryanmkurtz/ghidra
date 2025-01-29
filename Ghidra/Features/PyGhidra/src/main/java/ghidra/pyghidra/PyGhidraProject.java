package ghidra.pyghidra;

import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.ProjectData;
import ghidra.framework.project.DefaultProject;

public class PyGhidraProject extends DefaultProject {

	public PyGhidraProject(PyGhidraProjectManager projectManager, ProjectData projectData) {
		super(projectManager, (DefaultProjectData) projectData);
		AppInfo.setActiveProject(this);
	}
}