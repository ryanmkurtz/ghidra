package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code PLT_entry} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomPltEntry implements StructConverter {

	/** The size in bytes of a {@link SomPltEntry} */
	public static final int SIZE = 0x8;

	private int procAddr;
	private int ltptrValue;

	/**
	 * Creates a new {@link SomPltEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the PLT
	 * @throws IOException if there was an IO-related error
	 */
	public SomPltEntry(BinaryReader reader) throws IOException {
		procAddr = reader.readNextInt();
		ltptrValue = reader.readNextInt();
	}

	/**
	 * {@return the address of the procedure to be branched to}
	 */
	public int getProcAddr() {
		return procAddr;
	}

	/**
	 * {@return the import index of the code symbol (if {@code proc_addr} points to the BOR routine}
	 */
	public int getLtptrValue() {
		return ltptrValue;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("PLT_entry", SIZE);
		struct.setPackingEnabled(true);
		struct.add(POINTER, "poc_addr", "address of procedure");
		struct.add(DWORD, "ltptr_value", "value of r19 required for this procedure");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
