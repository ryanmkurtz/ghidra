package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code som_exec_auxhdr} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomUnknownAuxHeader extends SomAuxHeader {

	private byte[] bytes;

	/**
	 * Creates a new {@link SomUnknownAuxHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary header
	 * @throws IOException if there was an IO-related error
	 */
	public SomUnknownAuxHeader(BinaryReader reader) throws IOException {
		super(reader);
		bytes = reader.readNextByteArray((int) auxId.getLength());
	}

	/**
	 * {@return the unknown bytes of this auxiliary header}
	 */
	public byte[] getBytes() {
		return bytes;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("som_unknown_auxhdr", 0);
		struct.setPackingEnabled(true);
		struct.add(auxId.toDataType(), "som_auxhdr", null);
		struct.add(new ArrayDataType(BYTE, (int) auxId.getLength(), 1), "bytes", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}