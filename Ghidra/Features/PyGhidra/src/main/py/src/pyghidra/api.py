import sys
import contextlib
from typing import Union, TYPE_CHECKING, Tuple, Callable, Any

from pyghidra.converters import *  # pylint: disable=wildcard-import, unused-wildcard-import

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program
    from ghidra.framework.model import Project, DomainFile
    from ghidra.formats.gfilesystem import GFileSystem
    from ghidra.formats.gfilesystem import FSUtilities
    from ghidra.util.task import TaskMonitor
    from ghidra.app.script import GhidraScript
    from generic.jar import ResourceFile
    from java.lang import Object # type:ignore @UnresolvedImport
    from java.net import URI, URL # type:ignore @UnresolvedImport

def open_project(
        project_location: Union[str, Path],
        project_name: str,
        create: bool = False
) -> "Project": # type: ignore
    """
    Opens the Ghidra project at the given location, optionally creating it if it doesn't exist.

    :param project_location: Location of Ghidra project to open.
    :param project_name: Name of Ghidra project to open.
    :param create: Whether to create the project if it doesn't exist
    :return: A Ghidra "Project" object.
    :raises FileNotFoundError: If the project to open was not found and it shouldn't be created.
    """
    from ghidra.framework.protocol.ghidra import GhidraURLQuery
    from ghidra.framework.model import ProjectLocator
    from ghidra.pyghidra import PyGhidraProjectManager, PyGhidraURLResultHandler
    from ghidra.util.task import TaskMonitor
    from java.net import URL, URI # type:ignore @UnresolvedImport
    
    if project_location.startswith("ghidra"):
        try:
            ghidra_url = URI(project_location).toURL()
        except:
            raise FileNotFoundError(f'Invalid Ghidra URL: "{project_location}"!')
        handler = PyGhidraURLResultHandler()
        GhidraURLQuery.queryRepositoryUrl(ghidra_url, False, handler, TaskMonitor.DUMMY)
        return handler.project
    else:
        projectLocator = ProjectLocator(project_location, project_name);
        projectManager = PyGhidraProjectManager()
        if projectLocator.exists():
            return projectManager.openProject(projectLocator, False, True);
        elif create:
            return projectManager.createProject(projectLocator, None, True)
        raise FileNotFoundError(f'Project "{project_name}" not found at "{project_location}"!')

def open_filesystem(
        path: Union[str, Path]
    ) -> "GFileSystem":
    from java.io import File # type:ignore @UnresolvedImport
    from ghidra.formats.gfilesystem import FileSystemService
    from ghidra.util.task import TaskMonitor
    
    service = FileSystemService.getInstance()
    fsrl = service.getLocalFS().getLocalFSRL(File(path))
    return service.openFileSystemContainer(fsrl, TaskMonitor.DUMMY)

def get_program(
        project: "Project", 
        path: Union[str, Path],
        consumer: Any = None
    ) -> Tuple["Program", "Object"]:
    """
    Gets the program from the given project with the given name.

    :param project: The Ghidra project that has the program.
    :param path: The project path of the program (should start with "/")
    :param consumer: A reference to the Java object "consuming" the returned program, used to ensure
        the underlying DomainObject is only closed when every consumer is done with it.
    :return: A 2-element tuple containing the program and a consumer object that must be used to
        release the program when finished with it (i.e., program.release(consumer). If a consumer
        object was provided, the same consumer object is returned. Otherwise, a new consumer object
        is created and returned.
    :raises FileNotFoundError: If the path does not exist in the project.
    :raises TypeError: If the path in the project exists but is not a Program.
    """
    from ghidra.util.task import TaskMonitor
    from ghidra.program.model.listing import Program
    from java.lang import Object # type:ignore @UnresolvedImport
    if consumer is None:
        consumer = Object()
    project_data = project.getProjectData()
    df = project_data.getFile(path)
    if df is None:
        raise FileNotFoundError(f'"{path}" does not exist in the Project')
    dobj = df.getDomainObject(consumer, True, False, TaskMonitor.DUMMY)
    program_cls = Program.class_
    if not program_cls.isAssignableFrom(dobj.getClass()):
        dobj.release(consumer)
        raise TypeError(f'"{path}" exists but is not a Program')
    return dobj, consumer

def walk_project(
        project: "Project",
        callback: Callable[["DomainFile"], None],
        start: Union[str, Path] = "/"
    ):
    """
    Walks the the given project, calling the provided function when each domain file is encountered.

    :param project: The Ghidra project to walk.
    :param callback: The callback to process each domain file.
    :param start: An optional starting project folder path.
    :raises FileNotFoundError: If the starting folder is not found in the project.
    """
    from ghidra.framework.model import ProjectDataUtils
    start_folder = project.projectData.getFolder(start)
    if start_folder is None:
        raise FileNotFoundError(f'Starting folder "{start}" does not exist in the Project')
    for file in ProjectDataUtils.DomainFileIterator(start_folder):
        callback(file)

def walk_programs(
        project: "Project",
        callback: Callable[["DomainFile", "Program"], None],
        start: Union[str, Path] = "/"
    ):
    """
    Walks the the given project, calling the provided function when each Program is encountered.
    Non-programs in the project are skipped.

    :param project: The Ghidra project to walk.
    :param callback: The callback to process each Program.
    :param start: An optional starting project folder path.
    :raises FileNotFoundError: If the starting folder is not found in the project.
    """
    def process(file: "DomainFile"):
        try:
            program, consumer = get_program(project, file.getPathname())
            try:
                callback(file, program)
            finally:
                program.release(consumer)
        except TypeError:
            pass # skip over non-programs
    
    walk_project(project, process, start)
    
def ghidra_script(
        path: Union[str, Path],
        project: "Project",
        program: "Program" = None,
        echo_stdout = True,
        echo_stderr = True
    ) -> Tuple[str, str]:
    from generic.jar import ResourceFile
    from ghidra.app.script import GhidraScriptUtil, GhidraState, ScriptControls
    from ghidra.util.task import TaskMonitor
    from java.io import File, PrintWriter, StringWriter # type:ignore @UnresolvedImport
    from java.lang import System # type:ignore @UnresolvedImport

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        source_file = ResourceFile(File(path))
        if not source_file.exists():
            raise TypeError(f'"{str(source_file)}" was not found')
        provider = GhidraScriptUtil.getProvider(source_file)
        if provider is None:
            raise TypeError(f'"{path}" is not a supported GhidraScript')
        script = provider.getScriptInstance(source_file,  PrintWriter(System.out))
        if script is None:
            raise TypeError(f'"{str(source_file)}" was not found')
        state = GhidraState(None, project, program, None, None, None)
        stdout_string_writer = StringWriter()
        stderr_string_writer = StringWriter()
        controls = ScriptControls(
            PrintWriter(stdout_string_writer, True),
            PrintWriter(stderr_string_writer, True),
            TaskMonitor.DUMMY
        )
        script.execute(state, controls)
        stdout_str = str(stdout_string_writer)
        stderr_str = str(stderr_string_writer)
        if echo_stdout:
            sys.stdout.write(stdout_str)
            sys.stdout.flush()
        if echo_stderr:
            sys.stderr.write(stderr_str)
            sys.stderr.flush()
        return stdout_str, stderr_str
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
    
@contextlib.contextmanager
def transaction(
        program: "Program",
        description: str = "Unnamed Transaction"
    ):
    transaction_id = program.startTransaction(description)
    success = True
    try:
        yield transaction_id
    except:
        success = False
    finally:
        program.endTransaction(transaction_id, success)