package ghidra.app.plugin.core.analysis;

import java.util.List;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixups;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ExternalSymbolResolver;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class MachoLocalStubsFixupAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Mach-O Local Stubs Fixups";
	private static final String DESCRIPTION = "An analyzer to fixup local stubs relocations";

	/**
	 * Creates a new {@link MachoLocalStubsFixupAnalyzer} 
	 */
	public MachoLocalStubsFixupAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);

		// Needs to run after the xrefs on the got entries get created
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();
		return MachoLoader.MACH_O_NAME.equals(format);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Memory mem = program.getMemory();
		ReferenceManager refMgr = program.getReferenceManager();
		ExternalManager extMgr = program.getExternalManager();
		RelocationTable relocTable = program.getRelocationTable();
		FunctionManager functionMgr = program.getFunctionManager();
		Listing listing = program.getListing();

		MemoryBlock got = mem.getBlock(SectionNames.SECT_GOT);
		if (got == null) {
			return true;
		}
		monitor.initialize(got.getSize());
		for (Address addr = got.getStart(); addr.compareTo(got.getEnd()) < 0; addr = addr.add(8)) {
			monitor.increment(8);

			// Get the stub function that references each unsupported relocation
			List<Relocation> relocs = relocTable.getRelocations(addr);
			if (relocs.size() != 1) {
				continue;
			}
			Relocation reloc = relocs.getFirst();
			if (reloc.getType() != DyldChainedFixups.RELOCATION_TYPE ||
				reloc.getStatus() != Relocation.Status.UNSUPPORTED) {
				continue;
			}
			String name = reloc.getSymbolName();
			if (name.isEmpty()) {
				continue;
			}
			long[] relocValues = reloc.getValues();
			if (relocValues.length != 1) {
				continue;
			}
			int libraryIndex = (int) relocValues[0] - 1;
			List<String> libraries = ExternalSymbolResolver.getOrderedRequiredLibraryNames(program);
			if (libraryIndex < 0 || libraryIndex >= libraries.size()) {
				continue;
			}
			ReferenceIterator iter = refMgr.getReferencesTo(addr);
			Function stubFunc = null;
			while (iter.hasNext()) {
				Address fromAddr = iter.next().getFromAddress();
				Function func = functionMgr.getFunctionAt(fromAddr);
				if (func != null && func.getName().startsWith("STUB_")) {
					stubFunc = func;
					break;
				}
			}
			if (stubFunc == null) {
				continue;
			}

			// Perform the relocation and update the pointer data type
			try {
				mem.setLong(reloc.getAddress(), stubFunc.getEntryPoint().getOffset());
				listing.clearCodeUnits(addr, addr, false);
				DataUtilities.createData(program, addr, PointerDataType.dataType, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
			catch (MemoryAccessException | CodeUnitInsertionException e) {
				e.printStackTrace();
			}

			// Update the stub function and its thunk's external location
			try {
				stubFunc.setName(name, SourceType.IMPORTED);

				String libraryName = libraries.get(libraryIndex);
				Library library = extMgr.getExternalLibrary(libraryName);
				if (library != null) {
					ExternalLocation extLoc;
					Function thunk = stubFunc.getThunkedFunction(false);
					if (thunk != null) {
						extLoc = thunk.getExternalLocation();
						extLoc.setName(library, name, SourceType.IMPORTED);
					}
					else {
						extLoc = extMgr.addExtFunction(library, name, null, SourceType.IMPORTED);
						stubFunc.setThunkedFunction(extLoc.createFunction());
					}
				}
			}
			catch (DuplicateNameException | InvalidInputException e) {
				e.printStackTrace();
			}

		}
		
		return true;
	}

}
