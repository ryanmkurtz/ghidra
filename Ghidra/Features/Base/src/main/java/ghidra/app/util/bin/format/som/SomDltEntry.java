package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code DLT} value
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomDltEntry implements StructConverter {

	/** The size in bytes of a {@link SomDltEntry} */
	public static final int SIZE = 0x4;

	private int value;

	/**
	 * Creates a new {@link SomDltEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the DLT
	 * @throws IOException if there was an IO-related error
	 */
	public SomDltEntry(BinaryReader reader) throws IOException {
		value = reader.readNextInt();
	}

	/**
	 * {@return the value of the DLT entry}
	 */
	public int getValue() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return POINTER;
	}
}
