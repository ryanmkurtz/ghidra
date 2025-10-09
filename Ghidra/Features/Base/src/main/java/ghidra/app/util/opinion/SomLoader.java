package ghidra.app.util.opinion;

import static ghidra.program.model.data.DataUtilities.ClearDataMode.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.som.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for System Object Model files
 */
public class SomLoader extends AbstractProgramWrapperLoader {
	public final static String SOM_NAME = "System Object Model (SOM)";
	public final static long MIN_BYTE_LENGTH = 124;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		try {
			SomHeader header = new SomHeader(new BinaryReader(provider, false));
			if (header.hasValidMagic()) {
				List<QueryResult> results = QueryOpinionService.query(getName(),
					Integer.toString(header.getSystemId()), null);
				for (QueryResult result : results) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			}
		}
		catch (IOException e) {
			// that's ok, not a System Object Model
		}
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws IOException, CancelledException {
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		FileBytes fileBytes =
			MemoryBlockUtils.createFileBytes(program, settings.provider(), monitor);
		BinaryReader reader = new BinaryReader(settings.provider(), false);
		try {
			SomHeader header = new SomHeader(reader);
			processMemoryBlocks(program, fileBytes, header, log, monitor);
			processEntryPoint(program, header, log, monitor);
			markupHeaders(program, fileBytes, header, log, monitor);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	private void processMemoryBlocks(Program program, FileBytes fileBytes, SomHeader header,
			MessageLog log, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Processing memory blocks...");
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		List<SomSpace> spaces = header.getSpaces();
		List<SomSubspace> subspaces = header.getSubspaces();
		for (SomSubspace subspace : subspaces) {
			SomSpace space = spaces.get(subspace.getSpaceIndex());
			String name = subspace.getName();
			long initSize = subspace.getInitializationLength();
			long size = subspace.getSubspaceLength();
			if (size == 0) {
				log.appendMsg("Skipping subspace %s with 0 length".formatted(name));
				continue;
			}
			Address addr = addrSpace.getAddress(subspace.getSubspaceStart());
			if (initSize > 0) {
				MemoryBlockUtils.createInitializedBlock(program, false, subspace.getName(), addr,
					fileBytes, subspace.getFileLocInitValue(), initSize, "", space.getName(),
					subspace.isRead(), subspace.isWrite(), subspace.isExecute(), log);
				addr = addr.add(initSize);
			}
			if (size > initSize) {
				MemoryBlockUtils.createUninitializedBlock(program, false, subspace.getName(),
					addr, size - initSize, "", space.getName(), subspace.isRead(),
					subspace.isWrite(), subspace.isExecute(), log);
			}
		}
	}

	private void processEntryPoint(Program program, SomHeader header, MessageLog log,
			TaskMonitor monitor) throws Exception {
		monitor.setMessage("Processing entry point...");

		SymbolTable symbolTable = program.getSymbolTable();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		SomSpace space = header.getSpaces().get((int) header.getEntrySpace());
		SomSubspace subspace =
			header.getSubspaces().get((int) (space.getSubspaceIndex() + header.getEntrySubspace()));
		Address subspaceAddr = addrSpace.getAddress(subspace.getSubspaceStart());

		long entryOffset = 0;
		SomExecAuxHeader execHeader = header.getFirstAuxHeader(SomExecAuxHeader.class);
		if (execHeader != null) {
			long execEntry = execHeader.getExecEntry();
			if (execEntry != 0) {
				entryOffset = execEntry;
			}
		}
		if (entryOffset == 0) {
			entryOffset = header.getEntryOffset();
		}

		if (entryOffset != 0) {
			symbolTable.addExternalEntryPoint(subspaceAddr.add(entryOffset));
		}
	}

	private void markupHeaders(Program program, FileBytes fileBytes, SomHeader header,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
		try {
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"FILE", headerSpaceAddr, fileBytes, 0, fileBytes.getSize(), "", "", false, false,
				false, log);

			// Markup header
			Address start = headerBlock.getStart();
			DataUtilities.createData(program, start, header.toDataType(), -1, CHECK_FOR_SPACE);

			// Markup SomSpaces
			for (int i = 0; i < header.getSpaces().size(); i++) {
				SomSpace space = header.getSpaces().get(i);
				Address addr =
					start.add(header.getSpaceLocation() + i * SomSpace.SIZE);
				DataUtilities.createData(program, addr, space.toDataType(), -1, CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CommentType.EOL, space.getName());
			}

			// Markup SomSubspaces
			for (int i = 0; i < header.getSubspaces().size(); i++) {
				SomSubspace subspace = header.getSubspaces().get(i);
				Address addr =
					start.add(header.getSubspaceLocation() + i * SomSubspace.SIZE);
				DataUtilities.createData(program, addr, subspace.toDataType(), -1, CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CommentType.EOL, subspace.getName());
			}

			// Markup SomAuxHeaders
			Address auxHeaderAddr = start.add(header.getAuxHeaderLocation());
			for (SomAuxHeader auxHeader : header.getAuxHeaders()) {
				DataUtilities.createData(program, auxHeaderAddr, auxHeader.toDataType(), -1,
					CHECK_FOR_SPACE);
				auxHeaderAddr = auxHeaderAddr.add(auxHeader.getLength());
			}

			// Markup SomCompilationUnits
			for (int i = 0; i < header.getCompilationUnits().size(); i++) {
				SomCompilationUnit unit = header.getCompilationUnits().get(i);
				Address addr =
					start.add(header.getCompilerLocation() + i * SomCompilationUnit.SIZE);
				DataUtilities.createData(program, addr, unit.toDataType(), -1, CHECK_FOR_SPACE);
				program.getListing().setComment(addr, CommentType.EOL, unit.getName());
			}
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers: " + e.getMessage());
		}
	}

	@Override
	public String getName() {
		return SOM_NAME;
	}
}