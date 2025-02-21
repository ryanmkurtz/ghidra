/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.omf51.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for OMF-51 files
 */
public class Omf51Loader extends AbstractProgramWrapperLoader {
	public final static String OMF51_NAME = "Object Module Format (OMF-51)";
	public final static long MIN_BYTE_LENGTH = 11;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			OmfRecord first = factory.readNextRecord();
			if (factory.getStartRecordTypes().contains(first.getRecordType()) &&
				first.validCheckSum()) {
				List<QueryResult> results = QueryOpinionService.query(getName(), "8051", null);
				for (QueryResult result : results) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			}
		}
		catch (IOException | OmfException e) {
			// that's ok, not an OMF-51
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			List<OmfRecord> records = OmfUtils.readRecords(factory);
			processMemoryBlocks(program, fileBytes, records, log, monitor);
			markupRecords(program, fileBytes, records, log, monitor);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	private void processMemoryBlocks(Program program, FileBytes fileBytes, List<OmfRecord> records,
			MessageLog log, TaskMonitor monitor) throws Exception {
		List<Omf51SegmentDefs> allSegmentDefs = records.stream()
				.filter(Omf51SegmentDefs.class::isInstance)
				.map(Omf51SegmentDefs.class::cast)
				.toList();
		List<Omf51Content> contents = records.stream()
				.filter(Omf51Content.class::isInstance)
				.map(Omf51Content.class::cast)
				.toList();
		
		int relOffset = 0x1000;

		for (Omf51SegmentDefs segmentDefs : allSegmentDefs) {
			Map<Integer, Omf51Segment> segmentMap = segmentDefs.getSegmentMap();
			for (Omf51Content content : contents) {
				Omf51Segment segment = segmentMap.get(content.getSegId());
				if (segment == null) {
					continue;
				}
				AddressSpace space = getAddressSpace(program, segment);
				if (space == null) {
					throw new Exception("Unsupported address space for: " + segment);
				}
				Address addr;
				String blockName;
				if (content.getSegId() == 0) {
					// Absolute segment
					blockName = "<ABSOLUTE>";
					addr = space.getAddress(segment.base() + content.getOffset());
				}
				else {
					// Relocatable segment
					blockName = segment.name().str();
					if (blockName.isBlank()) {
						blockName = "<UNKNOWN>";
					}
					addr = space.getAddress(relOffset + content.getOffset());
					relOffset += 0x1000;
					switch (segment.relType()) {
						// TODO
					}
				}
				if (blockName.isEmpty()) {
					blockName = "<NONAME>";
				}
				MemoryBlockUtils.createInitializedBlock(program, false, blockName, addr,
					new ByteArrayInputStream(content.getDataBytes()), segment.size(), "", "",
					true, true, true, log, monitor);
				if (segment.getType() == Omf51Segment.CODE) {
					AbstractProgramLoader.markAsFunction(program, blockName, addr);
				}
			}
		}
	}

	private void markupRecords(Program program, FileBytes fileBytes, List<OmfRecord> records,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up records...");
		int size = records.stream().mapToInt(r -> r.getRecordLength() + 3).sum();
		try {
			Address recordSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"RECORDS", recordSpaceAddr, fileBytes, 0, size, "", "", false, false, false, log);
			Address start = headerBlock.getStart();

			for (OmfRecord record : records) {
				try {
					Data d = DataUtilities.createData(program, start.add(record.getRecordOffset()),
						record.toDataType(), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					StructConverter.setEndian(d, false);
				}
				catch (Exception e) {
					log.appendMsg("Failed to markup record type 0x%x at offset 0x%x. %s."
							.formatted(record.getRecordType(), record.getRecordOffset(),
								e.getMessage()));
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup records: " + e.getMessage());
		}
	}

	private AddressSpace getAddressSpace(Program program, Omf51Segment segmentDef) {
		String name = switch (segmentDef.getType()) {
			case Omf51Segment.CODE -> "CODE";
			case Omf51Segment.XDATA -> "EXTMEM";
			case Omf51Segment.DATA -> "INTMEM";
			case Omf51Segment.IDATA -> "INTMEM";
			case Omf51Segment.BIT -> "BITS";
			default -> null;
		};
		return name != null ? program.getAddressFactory().getAddressSpace(name) : null;
	}

	@Override
	public String getName() {
		return OMF51_NAME;
	}
}
