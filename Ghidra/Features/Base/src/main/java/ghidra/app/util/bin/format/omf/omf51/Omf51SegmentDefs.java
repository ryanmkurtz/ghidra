package ghidra.app.util.bin.format.omf.omf51;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Omf51SegmentDefs extends OmfRecord {

	private boolean largeSegmentId;
	private Map<Integer, Omf51Segment> segmentMap = new LinkedHashMap<>();
	
	/**
	 * Creates a new {@link Omf51SegmentDefs} record
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param largeSegmentId True if the segment ID is 2 bytes; false if 1 byte
	 * @throws IOException if an IO-related error occurred
	 */
	public Omf51SegmentDefs(BinaryReader reader, boolean largeSegmentId) throws IOException {
		super(reader);
		this.largeSegmentId = largeSegmentId;
	}

	@Override
	public void parseData() throws IOException, OmfException {
		while (dataReader.getPointerIndex() < dataEnd) {
			Omf51Segment segment = new Omf51Segment(dataReader, largeSegmentId);
			segmentMap.put(segment.id(), segment);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(Omf51RecordTypes.getName(recordType), 0);
		struct.add(BYTE, "type", null);
		struct.add(WORD, "length", null);
		for (Omf51Segment segment : segmentMap.values()) {
			struct.add(largeSegmentId ? WORD : BYTE, "id", null);
			struct.add(BYTE, "info", null);
			struct.add(BYTE, "rel type", null);
			struct.add(BYTE, "unused", null);
			struct.add(WORD, "base", null);
			struct.add(WORD, "size", null);
			struct.add(segment.name().toDataType(), segment.name().getDataTypeSize(), "name", null);
		}
		struct.add(BYTE, "checksum", null);

		struct.setCategoryPath(new CategoryPath(OmfUtils.CATEGORY_PATH));
		return struct;
	}

	/**
	 * Gets a {@link Map} of segment ID's to {@link Omf51Segment segments}, ordered by their record
	 * definition order
	 * 
	 * @return A {@link Map} of segment ID's to {@link Omf51Segment segments}, ordered by their 
	 *   record definition order
	 */
	public Map<Integer, Omf51Segment> getSegmentMap() {
		return segmentMap;
	}
}
