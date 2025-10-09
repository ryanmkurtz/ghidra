package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * A class for reading/creating SOM auxiliary headers
 */
public class SomAuxHeaderFactory {

	public static SomAuxHeader readNextAuxHeader(BinaryReader reader) throws IOException {
		long origReaderIndex = reader.getPointerIndex();
		SomAuxId auxId = new SomAuxId(reader);
		reader.setPointerIndex(origReaderIndex);

		return switch (auxId.getType()) {
			case SomConstants.EXEC_AUXILIARY_HEADER:
				yield new SomExecAuxHeader(reader);
			case SomConstants.LINKER_FOOTPRINT:
				yield new SomLinkerFootprintAuxHeader(reader);
			case SomConstants.PRODUCT_SPECIFICS:
				yield new SomProductSpecificsAuxHeader(reader);
			default:
				yield new SomUnknownAuxHeader(reader);
		};
	}
}
