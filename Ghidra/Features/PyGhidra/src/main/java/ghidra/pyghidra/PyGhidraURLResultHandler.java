package ghidra.pyghidra;

import java.io.IOException;
import java.net.URL;

import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.protocol.ghidra.GhidraURLResultHandlerAdapter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PyGhidraURLResultHandler extends GhidraURLResultHandlerAdapter {

	public Project project;

	@Override
	public void processResult(DomainFolder domainFolder, URL url,
			TaskMonitor monitor) throws IOException, CancelledException {
		project = new PyGhidraProject(new PyGhidraProjectManager(), domainFolder.getProjectData());
	}
}
