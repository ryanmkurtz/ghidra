package ghidra.app.util.bin.format.som;

import static ghidra.app.util.bin.format.som.SomConstants.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code header} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomHeader implements StructConverter {

	private int systemId;
	private int magic;
	private long versionId;
	private SomSysClock fileTime;
	private long entrySpace;
	private long entrySubspace;
	private long entryOffset;
	private long auxHeaderLocation;
	private long auxHeaderSize;
	private long somLength;
	private long presumedDp;
	private long spaceLocation;
	private long spaceTotal;
	private long subspaceLocation;
	private long subspaceTotal;
	private long loaderFixupLocation;
	private long loaderFixupTotal;
	private long spaceStringsLocation;
	private long spaceStringsSize;
	private long initArrayLocation;
	private long initArrayTotal;
	private long compilerLocation;
	private long compilerTotal;
	private long symbolLocation;
	private long symbolTotal;
	private long fixupRequestLocation;
	private long fixupRequestTotal;
	private long symbolStringsLocation;
	private long symbolStringsSize;
	private long unloadableSpLocation;
	private long unloadableSpSize;
	private long checksum;

	private Map<Integer, SomSpace> spaces = new LinkedHashMap<>();
	private List<SomSubspace> subspaces = new ArrayList<>();
	private List<SomAuxHeader> auxHeaders = new ArrayList<>();
	private List<SomCompilationUnit> compilationUnits = new ArrayList<>();

	/**
	 * Creates a new {@link SomHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the header
	 * @throws IOException if there was an IO-related error
	 */
	public SomHeader(BinaryReader reader) throws IOException {
		systemId = reader.readNextUnsignedShort();
		magic = reader.readNextUnsignedShort();
		versionId = reader.readNextUnsignedInt();
		fileTime = new SomSysClock(reader);
		entrySpace = reader.readNextUnsignedInt();
		entrySubspace = reader.readNextUnsignedInt();
		entryOffset = reader.readNextUnsignedInt();
		auxHeaderLocation = reader.readNextUnsignedInt();
		auxHeaderSize = reader.readNextUnsignedInt();
		somLength = reader.readNextUnsignedInt();
		presumedDp = reader.readNextUnsignedInt();
		spaceLocation = reader.readNextUnsignedInt();
		spaceTotal = reader.readNextUnsignedInt();
		subspaceLocation = reader.readNextUnsignedInt();
		subspaceTotal = reader.readNextUnsignedInt();
		loaderFixupLocation = reader.readNextUnsignedInt();
		loaderFixupTotal = reader.readNextUnsignedInt();
		spaceStringsLocation = reader.readNextUnsignedInt();
		spaceStringsSize = reader.readNextUnsignedInt();
		initArrayLocation = reader.readNextUnsignedInt();
		initArrayTotal = reader.readNextUnsignedInt();
		compilerLocation = reader.readNextUnsignedInt();
		compilerTotal = reader.readNextUnsignedInt();
		symbolLocation = reader.readNextUnsignedInt();
		symbolTotal = reader.readNextUnsignedInt();
		fixupRequestLocation = reader.readNextUnsignedInt();
		fixupRequestTotal = reader.readNextUnsignedInt();
		symbolStringsLocation = reader.readNextUnsignedInt();
		symbolStringsSize = reader.readNextUnsignedInt();
		unloadableSpLocation = reader.readNextUnsignedInt();
		unloadableSpSize = reader.readNextUnsignedInt();
		checksum = reader.readNextUnsignedInt();

		if (spaceLocation > 0) {
			reader.setPointerIndex(spaceLocation);
			for (int i = 0; i < spaceTotal; i++) {
				SomSpace space = new SomSpace(reader, spaceStringsLocation);
				spaces.put(space.getSpaceNumber(), space);
			}
		}

		if (subspaceLocation > 0) {
			reader.setPointerIndex(subspaceLocation);
			for (int i = 0; i < subspaceTotal; i++) {
				subspaces.add(new SomSubspace(reader, spaceStringsLocation));
			}
		}

		if (auxHeaderLocation > 0) {
			reader.setPointerIndex(auxHeaderLocation);
			long sizeRemaining = auxHeaderSize;
			while (sizeRemaining > 0) {
				SomAuxHeader auxHeader = SomAuxHeaderFactory.readNextAuxHeader(reader);
				auxHeaders.add(auxHeader);
				sizeRemaining -= auxHeader.getAuxId().getLength() + SomAuxId.SIZE;
			}
		}

		if (compilerLocation > 0) {
			reader.setPointerIndex(compilerLocation);
			for (int i = 0; i < compilerTotal; i++) {
				compilationUnits.add(new SomCompilationUnit(reader, symbolStringsLocation));
			}
		}
	}
	
	/**
	 * {@return the system ID}
	 */
	public int getSystemId() {
		return systemId;
	}

	/**
	 * {@return the magic}
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * {@return true if this {@link SomHeader} has a valid magic number; otherwise false}
	 */
	public boolean hasValidMagic() {
		return switch (magic) {
			case MAGIC_LIBRARY:
			case MAGIC_RELOCATABLE:
			case MAGIC_NON_SHAREABLE_EXE:
			case MAGIC_SHAREABLE_EXE:
			case MAGIC_SHARABLE_DEMAND_LOADABLE_EXE:
			case MAGIC_DYNAMIC_LOAD_LIBRARY:
			case MAGIC_SHARED_LIBRARY:
			case MAGIC_RELOCATABLE_LIBRARY:
				yield true;
			default:
				yield false;
		};
	}

	/**
	 * {@return the version ID}
	 */
	public long getVersionId() {
		return versionId;
	}

	/**
	 * {@return the file time}
	 */
	public SomSysClock getFileType() {
		return fileTime;
	}

	/**
	 * {@return the index of space containing entry point}
	 */
	public long getEntrySpace() {
		return entrySpace;
	}

	/**
	 * {@return the index of subspace for entry point}
	 */
	public long getEntrySubspace() {
		return entrySubspace;
	}

	/**
	 * {@return the offset of entry point}
	 */
	public long getEntryOffset() {
		return entryOffset;
	}

	/**
	 * {@return the auxiliary header location}
	 */
	public long getAuxHeaderLocation() {
		return auxHeaderLocation;
	}

	/**
	 * {@return the auxiliary header size}
	 */
	public long getAuxHeaderSize() {
		return auxHeaderSize;
	}

	/**
	 * {@return the length in bytes of entire som}
	 */
	public long getSomLength() {
		return somLength;
	}

	/**
	 * {@return the DP value assumed during compilation}
	 */
	public long getPresumedDp() {
		return presumedDp;
	}

	/**
	 * {@return the location in file of space dictionary}
	 */
	public long getSpaceLocation() {
		return spaceLocation;
	}

	/**
	 * {@return the number of space entries}
	 */
	public long getSpaceTotal() {
		return spaceTotal;
	}

	/**
	 * {@return the location of subspace entries}
	 */
	public long getSubspaceLocation() {
		return subspaceLocation;
	}

	/**
	 * {@return the number of subspace entries}
	 */
	public long getSubspaceTotal() {
		return subspaceTotal;
	}

	/**
	 * {@return the MPE/iX loader fixup location}
	 */
	public long getLoaderFixupLocation() {
		return loaderFixupLocation;
	}

	/**
	 * {@return the number of loader fixup records}
	 */
	public long getLoaderFixupTotal() {
		return loaderFixupTotal;
	}

	/**
	 * {@return the file location of string area for space and subspace names}
	 */
	public long getSpaceStringsLocation() {
		return spaceStringsLocation;
	}

	/**
	 * {@return the size of string area for space and subspace names}
	 */
	public long getSpaceStringsSize() {
		return spaceStringsSize;
	}

	/**
	 * {@return the init array location}
	 */
	public long getInitArrayLocation() {
		return initArrayLocation;
	}

	/**
	 * {@return the init array total}
	 */
	public long getInitArrayTotal() {
		return initArrayTotal;
	}

	/**
	 * {@return the location in file of module dictionary}
	 */
	public long getCompilerLocation() {
		return compilerLocation;
	}

	/**
	 * {@return the number of modules}
	 */
	public long getCompilerTotal() {
		return compilerTotal;
	}

	/**
	 * {@return the location in file of symbol dictionary}
	 */
	public long getSymbolLocation() {
		return symbolLocation;
	}

	/**
	 * {@return the number of symbol records}
	 */
	public long getSymbolTotal() {
		return symbolTotal;
	}

	/**
	 * {@return the location in file of fixup requests}
	 */
	public long getFixupRequestLocation() {
		return fixupRequestLocation;
	}

	/**
	 * {@return the number of fixup requests}
	 */
	public long getFixupRequestTotal() {
		return fixupRequestTotal;
	}

	/**
	 * {@return the file location of string area for module and symbol names}
	 */
	public long getSymbolStringsLocation() {
		return symbolStringsLocation;
	}

	/**
	 * {@return the size of string area for module and symbol names}
	 */
	public long getSymbolStringsSize() {
		return symbolStringsSize;
	}

	/**
	 * {@return the byte offset of first byte of data for unloadable spaces}
	 */
	public long getUnloadableSpLocation() {
		return unloadableSpLocation;
	}

	/**
	 * {@return the byte length of data for unloadable spaces}
	 */
	public long getUnloadableSpSize() {
		return unloadableSpSize;
	}

	/**
	 * {@return the checksum}
	 */
	public long getChecksum() {
		return checksum;
	}

	/**
	 * {@return the {@link List} of {@link SomSpace spaces}}
	 */
	public List<SomSpace> getSpaces() {
		return new ArrayList<>(spaces.values());
	}

	/**
	 * {@return the {@link List} of {@link SomSubspace subspaces}}
	 */
	public List<SomSubspace> getSubspaces() {
		return subspaces;
	}

	/**
	 * {@return the {@link List} of {@link SomAuxHeader auxiliary headers}}
	 */
	public List<SomAuxHeader> getAuxHeaders() {
		return auxHeaders;
	}

	/**
	 * {@return the {@link List} of {@link SomAuxHeader auxiliary headers}} of the given type}
	 * 
	 * @param <T> The type of auxiliary header to get
	 * @param classType The type of auxiliary header to get
	 */
	public <T> List<T> getAuxHeaders(Class<T> classType) {
		List<T> tmp = new ArrayList<>();
		for (SomAuxHeader auxHeader : auxHeaders) {
			if (classType.isAssignableFrom(auxHeader.getClass())) {
				tmp.add(classType.cast(auxHeader));
			}
		}
		return tmp;
	}

	/**
	 * {@return the first found {@link SomAuxHeader auxiliary header}} of the given type}
	 * 
	 * @param <T> The type of auxiliary header to get
	 * @param classType The type of auxiliary header to get
	 */
	public <T> T getFirstAuxHeader(Class<T> classType) {
		for (SomAuxHeader auxHeader : auxHeaders) {
			if (classType.isAssignableFrom(auxHeader.getClass())) {
				return classType.cast(auxHeader);
			}
		}
		return null;
	}

	/**
	 * {@return the {@link List} of {@link SomCompilationUnit compilation units}}
	 */
	public List<SomCompilationUnit> getCompilationUnits() {
		return compilationUnits;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("header", 0);
		struct.setPackingEnabled(true);
		struct.add(WORD, "system_id", "magic number - system");
		struct.add(WORD, "a_magic", "magic number - file type");
		struct.add(DWORD, "version_id", "version id; format=YYMMDDHH");
		struct.add(fileTime.toDataType(), "file_time", "system clock- zero if unused");
		struct.add(DWORD, "entry_space", "index of space containing entry point");
		struct.add(DWORD, "entry_subspace", "index of subspace for entry point");
		struct.add(DWORD, "entry_offset", "offset of entry point");
		struct.add(DWORD, "aux_header_location", "auxiliary header location");
		struct.add(DWORD, "aux_header_size", "auxiliary header size");
		struct.add(DWORD, "som_length", "length in bytes of entire som");
		struct.add(DWORD, "presumed_dp", "DP value assumed during compilation");
		struct.add(DWORD, "space_location", "location in file of space dictionary");
		struct.add(DWORD, "space_total", "number of space entries");
		struct.add(DWORD, "subspace_location", "location of subspace entries");
		struct.add(DWORD, "subspace_total", "number of subspace entries");
		struct.add(DWORD, "loader_fixup_location", "MPE/iX loader fixup");
		struct.add(DWORD, "loader_fixup_total", "number of loader fixup records");
		struct.add(DWORD, "space_strings_location",
			"file location of string area for space and subspace names");
		struct.add(DWORD, "space_strings_size", "size of string area for space and subspace names");
		struct.add(DWORD, "init_array_location", "reserved for use by system");
		struct.add(DWORD, "init_array_total", "reserved for use by system");
		struct.add(DWORD, "compiler_location", "location in file of module dictionary");
		struct.add(DWORD, "compiler_total", "number of modules");
		struct.add(DWORD, "symbol_location", "location in file of symbol dictionary");
		struct.add(DWORD, "symbol_total", "number of symbol records");
		struct.add(DWORD, "fixup_request_location", "location in file of fixup requests");
		struct.add(DWORD, "fixup_request_total", "number of fixup requests");
		struct.add(DWORD, "symbol_strings_location",
			"file location of string area for module and symbol names");
		struct.add(DWORD, "symbol_strings_size", "size of string area for module and symbol names");
		struct.add(DWORD, "unloadable_sp_location",
			"byte offset of first byte of data for unloadable spaces");
		struct.add(DWORD, "unloadable_sp_size", "byte length of data for unloadable spaces");
		struct.add(DWORD, "checksum", "");

		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}

}
