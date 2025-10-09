package ghidra.app.util.opinion;

import static ghidra.app.util.bin.format.som.SomConstants.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.som.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
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
			SomDynamicLoaderHeader dlHeader = new SomDynamicLoaderHeader(program,
				header.getTextAddress(program), header.getDataAddress(program));
			processEntryPoint(program, header, log, monitor);
			processSymbols(program, header, log, monitor);
			processImports(program, dlHeader, log, monitor);
			processLibraries(program, dlHeader, log, monitor);
			markupHeaders(program, fileBytes, header, dlHeader, log, monitor);
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
			long initSize = subspace.getInitializationLength();
			long size = subspace.getSubspaceLength();
			if (size == 0) {
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
			Address addr = subspaceAddr.add(entryOffset);
			program.getSymbolTable().createLabel(addr, "entry", SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(addr);
		}
	}

	private void processSymbols(Program program, SomHeader header, MessageLog log,
			TaskMonitor monitor) throws Exception {
		SymbolTable symbolTable = program.getSymbolTable();
		AddressSpace addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		List<SomSymbol> somSymbols = header.getSymbols();
		monitor.initialize(somSymbols.size(), "Processing symbols...");
		for (SomSymbol somSymbol : somSymbols) {
			monitor.increment();
			
			Address addr = addrSpace.getAddress(somSymbol.getSymbolValue());
//			String name = "%s_%d_%x_%x_%d".formatted(somSymbol.getName(), somSymbol.getSymbolType(),
//				somSymbol.getSymbolValue(), somSymbol.getSymbolInfo(), somSymbol.getSymbolScope());
			String name = somSymbol.getName();

			// For code symbols, mask off bottom 2 permission bits
			switch (somSymbol.getSymbolType()) {
				case SYMBOL_ENTRY:
				case SYMBOL_MILLICODE:
				case SYMBOL_CODE:
					addr = addr.getNewAddress(addr.getOffset() & 0xfffffffc);
			}

			// Create label on supported symbols
			switch (somSymbol.getSymbolType()) {
				case SYMBOL_ENTRY:
				case SYMBOL_MILLICODE:
				case SYMBOL_CODE:
				case SYMBOL_DATA:
				case SYMBOL_STUB:
					symbolTable.createLabel(addr, name, SourceType.IMPORTED);
			}

			// Create functions on relevant symbols
			switch (somSymbol.getSymbolType()) {
				case SYMBOL_ENTRY:
				case SYMBOL_MILLICODE:
					AbstractProgramLoader.markAsFunction(program, name, addr);
			}

			// Create entry points on relevant symbols
			switch (somSymbol.getSymbolScope()) {
				case SYMBOL_SCOPE_UNIVERSAL:
					symbolTable.addExternalEntryPoint(addr);
			}
		}
	}

	private void processImports(Program program, SomDynamicLoaderHeader dlHeader, MessageLog log,
			TaskMonitor monitor) throws Exception {
		int importCounter = 0;
		List<SomImportEntry> imports = dlHeader.getImports();
		List<SomDltEntry> dlt = dlHeader.getDlt();
		List<SomPltEntry> plt = dlHeader.getPlt();
		SymbolTable symbolTable = program.getSymbolTable();
		FunctionManager functionMgr = program.getFunctionManager();
		ExternalManager extMgr = program.getExternalManager();
		Address dataAddr = dlHeader.getDataAddress();

		monitor.initialize(dlt.size(), "Processing DLT imports...");
		for (int i = 0; i < dlt.size(); i++, importCounter++) {
			monitor.increment();
			SomImportEntry importEntry = imports.get(importCounter);
			String importName = importEntry.getName();
			if (importName != null) {
				SomDltEntry dltEntry = dlt.get(i);
				Address target = dataAddr.getNewAddress(dltEntry.getValue());
				symbolTable.createLabel(target, importName, SourceType.IMPORTED);
				extMgr.addExtLocation(Library.UNKNOWN, importName, null, SourceType.IMPORTED);
			}
		}

		monitor.initialize(plt.size(), "Processing PLT imports...");
		for (int i = 0; i < plt.size(); i++, importCounter++) {
			monitor.increment();
			SomImportEntry importEntry = imports.get(importCounter);
			SomPltEntry pltEntry = plt.get(i);
			Address target = dataAddr.getNewAddress(pltEntry.getProcAddr());
			String name = importEntry.getName();
			Function stubFunc = functionMgr.getFunctionAt(target);
			if (stubFunc == null) {
				stubFunc = functionMgr.createFunction(name, target, new AddressSet(target),
					SourceType.IMPORTED);
			}
			ExternalLocation loc =
				extMgr.addExtLocation(Library.UNKNOWN, name, null, SourceType.IMPORTED);
			stubFunc.setThunkedFunction(loc.createFunction());
		}
	}

	private void processLibraries(Program program, SomDynamicLoaderHeader dlHeader, MessageLog log,
			TaskMonitor monitor) throws Exception {
		monitor.initialize(dlHeader.getShlibListCount(), "Processing libraries...");
		for (SomShlibListEntry entry : dlHeader.getShlibs()) {
			String name = SymbolUtilities.replaceInvalidChars(entry.getShlibName(), true);
			try {
				program.getExternalManager().addExternalLibraryName(name, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				// do not care
			}
			catch (Exception e) {
				log.appendMsg("Unable to add external library name: " + e.getMessage());
			}
		}
	}

	private void markupHeaders(Program program, FileBytes fileBytes, SomHeader header,
			SomDynamicLoaderHeader dlHeader, MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
		try {
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"FILE", headerSpaceAddr, fileBytes, 0, fileBytes.getSize(), "", "", false, false,
				false, log);
			header.markup(program, headerBlock.getStart(), monitor);
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers: " + e.getMessage());
		}
		try {
			dlHeader.markup(program, monitor);
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup dynamic loader headers: " + e.getMessage());
		}
	}

	@Override
	public String getName() {
		return SOM_NAME;
	}
}