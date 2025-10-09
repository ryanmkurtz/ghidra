package ghidra.app.util.bin.format.som;

import static ghidra.program.model.data.DataUtilities.ClearDataMode.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a SOM {@code dl_header} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomDynamicLoaderHeader implements StructConverter {

	/** The size in bytes of a {@link SomDynamicLoaderHeader} */
	public static final int SIZE = 0x70;

	private int hdrVersion;
	private int ltptrValue;
	private int shlibListLoc;
	private int shlibListCount;
	private int importListLoc;
	private int importListCount;
	private int hashTableLoc;
	private int hashTableSize;
	private int exportListLoc;
	private int exportListCount;
	private int stringTableLoc;
	private int stringTableSize;
	private int drelocLoc;
	private int drelocCount;
	private int dltLoc;
	private int pltLoc;
	private int dltCount;
	private int pltCount;
	private short highwaterMark;
	private short flags;
	private int exportExtLoc;
	private int moduleLoc;
	private int moduleCount;
	private int elaborator;
	private int initializer;
	private int embeddedPath;
	private int initializerCount;
	private int tdsize;
	private int fastbindListLoc;

	private Address textAddr;
	private Address dataAddr;
	private List<SomShlibListEntry> shlibs = new ArrayList<>();
	private List<SomImportEntry> imports = new ArrayList<>();
	private List<SomPltEntry> plt = new ArrayList<>();
	private List<SomDltEntry> dlt = new ArrayList<>();
	private List<SomModuleEntry> modules = new ArrayList<>();

	/**
	 * Creates a new {@link SomDynamicLoaderHeader}
	 * 
	 * @param program The {@link Program}
	 * @param textAddr The {@link Address} of the "text" space
	 * @param dataAddr The {@link Address} of the "data" space
	 * @throws IOException if there was an IO-related error
	 */
	public SomDynamicLoaderHeader(Program program, Address textAddr, Address dataAddr)
			throws IOException {
		if (textAddr == null) {
			throw new IOException("Address of text space required to create dynamic loader header");
		}
		if (dataAddr == null) {
			throw new IOException("Address of data space required to create dynamic loader header");
		}
		BinaryReader textReader =
			new BinaryReader(new MemoryByteProvider(program.getMemory(), textAddr), false);
		BinaryReader dataReader =
			new BinaryReader(new MemoryByteProvider(program.getMemory(), dataAddr), false);

		hdrVersion = textReader.readNextInt();
		ltptrValue = textReader.readNextInt();
		shlibListLoc = textReader.readNextInt();
		shlibListCount = textReader.readNextInt();
		importListLoc = textReader.readNextInt();
		importListCount = textReader.readNextInt();
		hashTableLoc = textReader.readNextInt();
		hashTableSize = textReader.readNextInt();
		exportListLoc = textReader.readNextInt();
		exportListCount = textReader.readNextInt();
		stringTableLoc = textReader.readNextInt();
		stringTableSize = textReader.readNextInt();
		drelocLoc = textReader.readNextInt();
		drelocCount = textReader.readNextInt();
		dltLoc = textReader.readNextInt();
		pltLoc = textReader.readNextInt();
		dltCount = textReader.readNextInt();
		pltCount = textReader.readNextInt();
		highwaterMark = textReader.readNextShort();
		flags = textReader.readNextShort();
		exportExtLoc = textReader.readNextInt();
		moduleLoc = textReader.readNextInt();
		moduleCount = textReader.readNextInt();
		elaborator = textReader.readNextInt();
		initializer = textReader.readNextInt();
		embeddedPath = textReader.readNextInt();
		initializerCount = textReader.readNextInt();
		tdsize = textReader.readNextInt();
		fastbindListLoc = textReader.readNextInt();

		this.textAddr = textAddr;
		this.dataAddr = dataAddr;

		if (shlibListLoc > 0) {
			textReader.setPointerIndex(shlibListLoc);
			for (int i = 0; i < shlibListCount; i++) {
				shlibs.add(new SomShlibListEntry(textReader, stringTableLoc));
			}
		}

		if (importListCount > 0) {
			textReader.setPointerIndex(importListLoc);
			for (int i = 0; i < importListCount; i++) {
				imports.add(new SomImportEntry(textReader, stringTableLoc));
			}
		}

		if (pltCount > 0) {
			dataReader.setPointerIndex(pltLoc);
			for (int i = 0; i < pltCount; i++) {
				plt.add(new SomPltEntry(dataReader));
			}
		}

		if (dltCount > 0) {
			dataReader.setPointerIndex(dltLoc);
			for (int i = 0; i < dltCount; i++) {
				dlt.add(new SomDltEntry(dataReader));
			}
		}

		if (moduleCount > 0) {
			textReader.setPointerIndex(moduleLoc);
			for (int i = 0; i < moduleCount; i++) {
				modules.add(new SomModuleEntry(textReader));
			}
		}
	}

	/**
	 * {@return the version of the DL header}
	 */
	public int getHdrVersion() {
		return hdrVersion;
	}

	/**
	 * {@return the data-relative offset of the Linkage Table pointer}
	 */
	public int getLtptrValue() {
		return ltptrValue;
	}

	/**
	 * {@return the text-relative offset of the shared library list}
	 */
	public int getShlibListLoc() {
		return shlibListLoc;
	}

	/**
	 * {@return the number of entries in the shared library list}
	 */
	public int getShlibListCount() {
		return shlibListCount;
	}

	/**
	 * {@return the text-relative offset of the import list}
	 */
	public int getImportListLoc() {
		return importListLoc;
	}

	/**
	 * {@return the number of entries in the import list}
	 */
	public int getImportListCount() {
		return importListCount;
	}

	/**
	 * {@return the text-relative offset of the hash table}
	 */
	public int getHashTableLoc() {
		return hashTableLoc;
	}

	/**
	 * {@return the number of slots used in the hash table}
	 */
	public int getHashTableSize() {
		return hashTableSize;
	}

	/**
	 * {@return the text-relative offset of the export list}
	 */
	public int getExportListLoc() {
		return exportListLoc;
	}

	/**
	 * {@return the number of export entries}
	 */
	public int getExportListCount() {
		return exportListCount;
	}

	/**
	 * {@return the text-relative offset of the string table}
	 */
	public int getStringTableLoc() {
		return stringTableLoc;
	}

	/**
	 * {@return the length of the string table}
	 */
	public int getStringTableSize() {
		return stringTableSize;
	}

	/**
	 * {@return the text-relative offset of the dynamic relocation records}
	 */
	public int getDrelocLoc() {
		return drelocLoc;
	}

	/**
	 * {@return the number of dynamic relocation records generated}
	 */
	public int getDrelocCount() {
		return drelocCount;
	}

	/**
	 * {@return the offset in the $DATA$ space of the Data Linkage Table}
	 */
	public int getDltLoc() {
		return dltLoc;
	}

	/**
	 * {@return the offset in the $DATA$ space of the Procedure Linkage Table}
	 */
	public int getPltLoc() {
		return pltLoc;
	}

	/**
	 * {@return the number of entries in the DLT}
	 */
	public int getDltCount() {
		return dltCount;
	}

	/**
	 * {@return the number of entries in the PLT}
	 */
	public int getPltCount() {
		return pltCount;
	}

	/**
	 * {@return the highest version number of any symbol defined in the shared library or in the
	 * set of highwater marks of the shared libraries in the shared library list}
	 */
	public short getHighwaterMark() {
		return highwaterMark;
	}

	/**
	 * {@return the flags}
	 */
	public short getFlags() {
		return flags;
	}

	/**
	 * {@return the text-relative offset of the export extension table}
	 */
	public int getExportExtLoc() {
		return exportExtLoc;
	}

	/**
	 * {@return the text-relative offset of the module table}
	 */
	public int getModuleLoc() {
		return moduleLoc;
	}

	/**
	 * {@return the number of modules in the module table}
	 */
	public int getModuleCount() {
		return moduleCount;
	}

	/**
	 * {@return the index into the import table if the elab_ref bit in the flags field is set}
	 */
	public int getElaborator() {
		return elaborator;
	}

	/**
	 * {@return the index into the import table if the init_ref bit in the flags field is set and 
	 * the initializer_count field is set 0}
	 */
	public int getInitializer() {
		return initializer;
	}

	/**
	 * {@return the index into the shared library string table}
	 */
	public int getEmbeddedPath() {
		return embeddedPath;
	}

	/**
	 * {@return the number of initializers declared}
	 */
	public int getInitializerCount() {
		return initializerCount;
	}

	/**
	 * {@return the size of the TSD area}
	 */
	public int getTdsize() {
		return tdsize;
	}

	/**
	 * {@return the text-relative offset of fastbind info}
	 */
	public int getFastbindListLoc() {
		return fastbindListLoc;
	}

	/**
	 * {@return the {@link Address} of the "text" space}
	 */
	public Address getTextAddress() {
		return textAddr;
	}

	/**
	 * {@return the {@link Address} of the "data" space}
	 */
	public Address getDataAddress() {
		return dataAddr;
	}

	/**
	 * {@return the {@link List} of {@link SomShlibListEntry shared library entries}}
	 */
	public List<SomShlibListEntry> getShlibs() {
		return shlibs;
	}

	/**
	 * {@return the {@link List} of {@link SomImportEntry import entries}}
	 */
	public List<SomImportEntry> getImports() {
		return imports;
	}

	/**
	 * {@return the {@link List} of {@link SomPltEntry PLT entries}}
	 */
	public List<SomPltEntry> getPlt() {
		return plt;
	}

	/**
	 * {@return the {@link List} of {@link SomDltEntry DLT entries}}
	 */
	public List<SomDltEntry> getDlt() {
		return dlt;
	}

	/**
	 * {@return the {@link List} of {@link SomModuleEntry module entries}}
	 */
	public List<SomModuleEntry> getModules() {
		return modules;
	}

	/**
	 * Marks up this header
	 * 
	 * @param program The {@link Program}
	 * @param monitor A cancellable monitor
	 * @throws Exception if there was a problem during markup
	 */
	public void markup(Program program, TaskMonitor monitor) throws Exception {
		DataUtilities.createData(program, textAddr, toDataType(), -1, CHECK_FOR_SPACE);

		monitor.initialize(shlibListCount, "Marking up shared library list...");
		for (int i = 0; i < shlibListCount; i++) {
			monitor.increment();
			SomShlibListEntry shlib = shlibs.get(i);
			Address addr = textAddr.add(shlibListLoc + i * SomShlibListEntry.SIZE);
			DataUtilities.createData(program, addr, shlib.toDataType(), -1, CHECK_FOR_SPACE);
			program.getListing().setComment(addr, CommentType.EOL, shlib.getShlibName());
		}
		
		monitor.initialize(importListCount, "Marking up imports list...");
		for (int i = 0; i < importListCount; i++) {
			monitor.increment();
			SomImportEntry entry = imports.get(i);
			Address addr = textAddr.add(importListLoc + i * SomImportEntry.SIZE);
			DataUtilities.createData(program, addr, entry.toDataType(), -1, CHECK_FOR_SPACE);
			program.getListing().setComment(addr, CommentType.EOL, entry.getName());
		}

		monitor.initialize(dltCount, "Marking up DLT entries...");
		for (int i = 0; i < dltCount; i++) {
			monitor.increment();
			SomDltEntry entry = dlt.get(i);
			Address addr = dataAddr.add(dltLoc + i * SomDltEntry.SIZE);
			DataUtilities.createData(program, addr, entry.toDataType(), -1, CHECK_FOR_SPACE);
		}

		monitor.initialize(pltCount, "Marking up PLT entries...");
		for (int i = 0; i < pltCount; i++) {
			monitor.increment();
			SomPltEntry entry = plt.get(i);
			Address addr = dataAddr.add(pltLoc + i * SomPltEntry.SIZE);
			DataUtilities.createData(program, addr, entry.toDataType(), -1, CHECK_FOR_SPACE);
		}

		monitor.initialize(dltCount, "Marking up modules list...");
		for (int i = 0; i < moduleCount; i++) {
			monitor.increment();
			SomModuleEntry entry = modules.get(i);
			Address addr = textAddr.add(moduleLoc + i * SomModuleEntry.SIZE);
			DataUtilities.createData(program, addr, entry.toDataType(), -1, CHECK_FOR_SPACE);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dl_header", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "hdr_version", "header version number");
		struct.add(DWORD, "ltptr_value", "data offset of LT pointer (R19)");
		struct.add(DWORD, "shlib_list_loc", "text offset of shlib list");
		struct.add(DWORD, "shlib_list_count", "count of items in shlib list");
		struct.add(DWORD, "import_list_loc", "text offset of import list");
		struct.add(DWORD, "import_list_count", "count of items in import list");
		struct.add(DWORD, "hash_table_loc", "text offset of export hash table");
		struct.add(DWORD, "hash_table_size", "count of slots in export hash table");
		struct.add(DWORD, "export_list_loc", "text offset of export list");
		struct.add(DWORD, "export_list_count", "count of items in export list");
		struct.add(DWORD, "string_table_loc", "text offset of string table");
		struct.add(DWORD, "string_table_size", "length in bytes of string table");
		struct.add(DWORD, "dreloc_loc", "text offset of dynamic reloc records");
		struct.add(DWORD, "dreloc_count", "number of dynamic relocation records");
		struct.add(DWORD, "dlt_loc", "data offset of data linkage table");
		struct.add(DWORD, "plt_loc", "data offset of procedure linkage table");
		struct.add(DWORD, "dlt_count", "number of dlt entries in linkage table");
		struct.add(DWORD, "plt_count", "number of plt entries in linkage table");
		struct.add(WORD, "highwater_mark", "highest version number seen in lib or in shlib list");
		struct.add(WORD, "flags", "various flags");
		struct.add(DWORD, "export_ext_loc", "text offset of export extension tbl");
		struct.add(DWORD, "module_loc", "text offset of module table");
		struct.add(DWORD, "module_count", "number of module entries");
		struct.add(DWORD, "elaborator", "import index of elaborator");
		struct.add(DWORD, "initializer", "import index of initializer");
		struct.add(DWORD, "embedded_path", "index into string table for search path");
		struct.add(DWORD, "initializer_count", "count of items in initializer import list");
		struct.add(DWORD, "tdsize", "size of the TSD area");
		struct.add(DWORD, "fastbind_list_loc", "text-relative offset of fastbind info");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
