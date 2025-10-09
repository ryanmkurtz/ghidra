package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class SomCompilationUnit implements StructConverter {

	/** The size in bytes of a {@link SomCompilationUnit} */
	public static final int SIZE = 0x24;

	private long nameIndex;
	private long languageNameIndex;
	private long productIdIndex;
	private long versionIdIndex;
	private int reserved;
	private boolean chunkFlag;
	private SomSysClock compileTime;
	private SomSysClock sourceTime;

	private String name;
	private String languageName;
	private String productId;
	private String versionId;

	/**
	 * Creates a new {@link SomCompilationUnit}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param symbolStringsLocation The starting index of the symbol strings
	 * @throws IOException if there was an IO-related error
	 */
	public SomCompilationUnit(BinaryReader reader, long symbolStringsLocation) throws IOException {
		nameIndex = reader.readNextUnsignedInt();
		languageNameIndex = reader.readNextUnsignedInt();
		productIdIndex = reader.readNextUnsignedInt();
		versionIdIndex = reader.readNextUnsignedInt();
		int bitfield = reader.readNextInt();
		chunkFlag = (bitfield & 0x1) != 0;
		reserved = (bitfield >> 1) & 0x7fffffff;
		compileTime = new SomSysClock(reader);
		sourceTime = new SomSysClock(reader);
		
		name = reader.readAsciiString(symbolStringsLocation + nameIndex);
		languageName = reader.readAsciiString(symbolStringsLocation + languageNameIndex);
		productId = reader.readAsciiString(symbolStringsLocation + productIdIndex);
		versionId = reader.readAsciiString(symbolStringsLocation + versionIdIndex);
	}

	/**
	 * {@return the compilation unit name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the language name}
	 */
	public String getLanguageName() {
		return languageName;
	}
	
	/**
	 * {@return the product ID}
	 */
	public String getProductId() {
		return productId;
	}

	/**
	 * {@return the version ID}
	 */
	public String getVersionId() {
		return versionId;
	}

	/**
	 * {@return the reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return whether or not the compilation unit is not the first SOM in a multiple chunk
	 * compilation}
	 */
	public boolean getChunkFlag() {
		return chunkFlag;
	}

	/**
	 * {@return the compile time}
	 */
	public SomSysClock getCompileTime() {
		return compileTime;
	}

	/**
	 * {@return the source time}
	 */
	public SomSysClock getSourceTime() {
		return sourceTime;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("compilation_unit", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "name", name);
		struct.add(DWORD, "language_name", languageName);
		struct.add(DWORD, "product_id", productId);
		struct.add(DWORD, "version_id", versionId);
		try {
			struct.addBitField(DWORD, 31, "reserved", null);
			struct.addBitField(DWORD, 1, "chunk_flag", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(compileTime.toDataType(), "compile_time", null);
		struct.add(sourceTime.toDataType(), "source_time", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
