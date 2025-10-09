package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public abstract class SomAuxHeader implements StructConverter {

	protected SomAuxId auxId;

	/**
	 * Creates a new {@link SomAuxHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary header
	 * @throws IOException if there was an IO-related error
	 */
	public SomAuxHeader(BinaryReader reader) throws IOException {
		auxId = new SomAuxId(reader);
	}

	/**
	 * {@return this {@link SomAuxHeader}'s {@link SomAuxId aux ID}}
	 */
	public SomAuxId getAuxId() {
		return auxId;
	}

	/**
	 * {@return the length in bytes of this {@link SomAuxHeader auxiliary header} (including the
	 * size of the aux id)}
	 */
	public long getLength() {
		return auxId.getLength() + SomAuxId.SIZE;
	}

	@Override
	public abstract DataType toDataType() throws DuplicateNameException, IOException;
}
