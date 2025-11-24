package ghidra.app.util.bin.format.swift.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class TargetMethodDescriptor extends SwiftTypeMetadataStructure {

	private int flags;
	private int impl;

	/**
	 * Creates a new {@link TargetMethodDescriptor}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public TargetMethodDescriptor(BinaryReader reader) throws IOException {
		super(reader.getPointerIndex());
		flags = reader.readNextInt();
		impl = reader.readNextInt();
	}

	/**
	 * Gets the flags
	 * 
	 * @return The flags
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Gets the method implementation's relative offset
	 * 
	 * @return The method implementation's relative offset
	 */
	public int getImpl() {
		return impl;
	}

	@Override
	public String getStructureName() {
		return TargetMethodDescriptor.class.getSimpleName();
	}

	@Override
	public String getDescription() {
		return "method descriptor";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(getStructureName(), 0);
		struct.add(DWORD, "Flags", "Flags describing the method");
		struct.add(SwiftUtils.PTR_RELATIVE, "Impl", "The method implementation");
		struct.setCategoryPath(new CategoryPath(DATA_TYPE_CATEGORY));
		return struct;
	}
}
