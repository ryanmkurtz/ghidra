package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class SomLinkerFootprintAuxHeader extends SomAuxHeader {

	private String productId;
	private String versionId;
	private SomSysClock htime;

	/**
	 * Creates a new {@link SomLinkerFootprintAuxHeader}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the auxiliary header
	 * @throws IOException if there was an IO-related error
	 */
	public SomLinkerFootprintAuxHeader(BinaryReader reader) throws IOException {
		super(reader);
		productId = reader.readNextAsciiString(12);
		versionId = reader.readNextAsciiString(12);
		htime = new SomSysClock(reader);
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
	 * {@return the htime}
	 */
	public SomSysClock getHtime() {
		return htime;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("linker_footprint", 0);
		struct.setPackingEnabled(true);
		struct.add(auxId.toDataType(), "som_auxhdr", null);
		struct.add(STRING, 12, "product_id", null);
		struct.add(STRING, 8, "version_id", null);
		struct.add(htime.toDataType(), "htime", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}

}
