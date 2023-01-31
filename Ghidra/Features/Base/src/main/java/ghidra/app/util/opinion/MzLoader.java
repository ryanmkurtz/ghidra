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

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for processing old-style DOS MZ executables
 * 
 * @see <a href="https://wiki.osdev.org/MZ">OSDev.org MZ</a> 
 * @see <a href="https://www.tavi.co.uk/phobos/exeformat.html">Notes on the format of DOS .EXE files</a> 
 * @see <a href="https://thestarman.pcministry.com/asm/debug/Segments.html">Removing the Mystery from SEGMENT : OFFSET Addressing</a> 
 */
public class MzLoader extends AbstractLibrarySupportLoader {
	public final static String MZ_NAME = "Old-style DOS Executable (MZ)";

	private final static String ENTRY_NAME = "entry";
	private final static int INITIAL_SEGMENT_VAL = 0x1000;
	private static final long MIN_BYTE_LENGTH = 4;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		MzExecutable mz = new MzExecutable(provider);
		OldDOSHeader header = mz.getHeader();
		if (header.isDosSignature() && !header.hasNewExeHeader() && !header.hasPeHeader()) {
			List<QueryResult> results =
				QueryOpinionService.query(getName(), "" + header.e_magic(), null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressFactory af = program.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		MzExecutable mz = new MzExecutable(provider);

		try {
			Set<RelocationFixup> relocationFixups = getRelocationFixups(space, mz, log, monitor);

			markupHeaders(program, fileBytes, mz, log, monitor);
			processMemoryBlocks(program, fileBytes, space, mz, relocationFixups, log, monitor);
			processRelocations(program, space, mz, relocationFixups, log, monitor);
			processEntryPoint(program, space, mz, log, monitor);
			processRegisters(program, mz, log, monitor);
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getName() {
		return MZ_NAME;
	}

	@Override
	public int getTierPriority() {
		return 60; // we are less priority than PE!  Important for AutoImporter
	}

	/**
	 * Stores a relocation's fixup information
	 * 
	 * @param fileOffset The file offset of the relocation
	 * @param target The target address of the relocation
	 */
	private record RelocationFixup(int fileOffset, SegmentedAddress target, int targetFileOffset,
			boolean isCode) {}

	/**
	 * Stores a segment boundary as 2 adjacent addresses (where one segment ends and another begins)
	 * 
	 * @param a The end address of the first adjacent segment
	 * @param b The start address of the second adjacent segment
	 * @param isCode True if the first segment is code; false if it is data
	 */
	private record SegmentBoundary(SegmentedAddress a, SegmentedAddress b, boolean isCode) {}

	private void markupHeaders(Program program, FileBytes fileBytes, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		OldDOSHeader header = mz.getHeader();
		int blockSize = paragraphsToBytes(header.e_cparhdr());
		try {
			Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"HEADER", headerSpaceAddr, fileBytes, 0, blockSize, "", "", false,
				false, false, log);
			Address addr = headerBlock.getStart();

			// Header
			DataUtilities.createData(program, addr, mz.getHeader().toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// Relocation Table
			List<MzRelocation> relocations = mz.getRelocations();
			if (!relocations.isEmpty()) {
				DataType relocationType = relocations.get(0).toDataType();
				int len = relocationType.getLength();
				addr = addr.add(header.e_lfarlc());
				for (int i = 0; i < relocations.size(); i++) {
					monitor.checkCanceled();
					DataUtilities.createData(program, addr.add(i * len), relocationType, -1,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
			}

		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers");
		}
	}

	private void processMemoryBlocks(Program program, FileBytes fileBytes,
			SegmentedAddressSpace space, MzExecutable mz, Set<RelocationFixup> relocationFixups,
			MessageLog log, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Building memory map...");

		OldDOSHeader header = mz.getHeader();

		List<RelocationFixup> orderedFixups = new ArrayList<>(relocationFixups);
		orderedFixups.sort((a, b) -> {
			int segment1 = a.target().getSegment();
			int segment2 = b.target().getSegment();
			if (segment1 == segment2) {
				int offset1 = a.target().getSegmentOffset();
				int offset2 = b.target().getSegmentOffset();
				return Integer.valueOf(offset1).compareTo(offset2);
			}
			return Integer.valueOf(segment1).compareTo(segment2);
		});
		orderedFixups.forEach(rf -> Msg.debug(this, rf));

		int blockFileOffset = paragraphsToBytes(header.e_cparhdr());
		SegmentedAddress blockStart = space.getAddress(INITIAL_SEGMENT_VAL, 0);
		for (int i = 0;; i++) {
			SegmentBoundary boundary =
				findSegmentBoundary(orderedFixups, (SegmentedAddress) blockStart.add(1), mz);

			long blockLen = boundary.a.subtract(blockStart);
			
			long dataRemaining = 0;
			String blockName = "CODE_" + i;
			boolean r = true;
			boolean w = false;
			boolean x = true;
			if (boundary.b == null || !boundary.isCode) {
				dataRemaining = 0x10000 - blockLen;
				blockName = "DATA";
				w = true;
				x = false;
			}

			MemoryBlock lastBlock =
				MemoryBlockUtils.createInitializedBlock(program, false, blockName, blockStart,
					fileBytes, blockFileOffset, blockLen, "", "mz", r, w, x, log);

			if (boundary.b == null) {
				if (dataRemaining > 0) {
					MemoryBlockUtils.createUninitializedBlock(program, false, blockName,
						lastBlock.getEnd().add(1), dataRemaining, "", "mz", r, w, x, log);
				}
				break;
			}

			blockStart = boundary.b;
			blockFileOffset = (int) (blockFileOffset + blockLen);
		}
	}

	private SegmentBoundary findSegmentBoundary(List<RelocationFixup> orderedFixups,
			SegmentedAddress startAddr, MzExecutable mz) throws Exception {

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();
		
		SegmentedAddress searchAddr = startAddr;
		RelocationFixup nextFixup = null;
		int stopOffset = fileSize(header);
		boolean isCode = true;

		for (int i = 0; i < orderedFixups.size(); i++) {
			RelocationFixup current = orderedFixups.get(i);
			if (current.target.getSegment() > startAddr.getSegment()) {
				if (i + 1 < orderedFixups.size() &&
					orderedFixups.get(i + 1).target.getSegment() == current.target.getSegment()) {
					continue;
				}
				stopOffset = Math.min(current.targetFileOffset, stopOffset);
				nextFixup = current;
				if (i > 0) {
					RelocationFixup prev = orderedFixups.get(i - 1);
					if (prev.target.getSegment() == startAddr.getSegment()) {
						searchAddr = prev.target;
						isCode = prev.isCode;
					}
					break;
				}
			}
		}

		// Search for end of segments
		int startOffset = addressToFileOffset(searchAddr.getSegment() - INITIAL_SEGMENT_VAL,
			searchAddr.getSegmentOffset(), header);
		int i = startOffset;
		SegmentedAddress a = null;
		SegmentedAddress b = null;
		do {
			i = findTerminator(i, stopOffset, reader);
			a = (SegmentedAddress) searchAddr.add(i - startOffset);
			if (nextFixup != null) {
				int difference = nextFixup.targetFileOffset - i;
				if (nextFixup.target.getSegmentOffset() >= difference) {
					b = (SegmentedAddress) nextFixup.target.subtract(difference);
					break;
				}
			}
		}
		while (i < stopOffset);

		return new SegmentBoundary(a, b, isCode);

	}

	private int findTerminator(int startOffset, int stopOffset, BinaryReader reader)
			throws IOException {
		final byte RETF_N = (byte) 0xca;
		final byte RETF = (byte) 0xcb;
		final byte IRET = (byte) 0xcf;
		final byte PUSH_BP = (byte) 0x55;
		final byte POP_BP = (byte) 0x5d;

		reader.setPointerIndex(startOffset);
		
		int i = startOffset;
		while (i < stopOffset) {
			switch (reader.readByte(i)) {
				case RETF_N: {
					byte prev = reader.readByte(i - 1);
					i += 3;
					byte next = i < stopOffset ? reader.readByte(i) : -1;
					if (prev == POP_BP || next == PUSH_BP) {
						return i;
					}
				}
				case RETF: {
					byte prev = reader.readByte(i - 1);
					i += 1;
					byte next = i < stopOffset ? reader.readByte(i) : -1;
					if (prev == POP_BP || next == PUSH_BP) {
						return i;
					}
				}
				case IRET: {
					byte prev = reader.readByte(i - 1);
					i += 1;
					byte next = i < stopOffset ? reader.readByte(i) : -1;
					if (prev == POP_BP || next == PUSH_BP) {
						return i;
					}
				}
				default: {
					i++;
				}
			}
		}

		return stopOffset;
	}

	private void processRelocations(Program program, SegmentedAddressSpace space, MzExecutable mz,
			Set<RelocationFixup> relocationFixups, MessageLog log, TaskMonitor monitor)
			throws Exception {
		monitor.setMessage("Processing relocations...");
		Memory memory = program.getMemory();

		for (RelocationFixup relocationFixup : relocationFixups) {
			Status status = Status.FAILURE;
			List<Address> relocationAddresses =
				memory.locateAddressesForFileOffset(relocationFixup.fileOffset());
			if (relocationAddresses.isEmpty()) {
				log.appendMsg("Memory block not found for file offset: " +
					relocationFixup.fileOffset() + ".  Skipping relocation");
				continue;
			}
			SegmentedAddress relocationAddress = (SegmentedAddress) relocationAddresses.get(0);
			int relocatedSegment = relocationFixup.target().getSegment();
			try {
				status = Status.APPLIED;
				memory.setShort(relocationAddress, (short) relocatedSegment);
			}
			catch (MemoryAccessException e) {
				log.appendMsg(String.format("Failed to apply relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}

			// Add to relocation table
			program.getRelocationTable()
					.add(relocationAddress, status, 0, new long[] { relocationAddress.getSegment(),
						relocationAddress.getSegmentOffset(), relocatedSegment }, 2, null);


		}
	}

	private void processEntryPoint(Program program, SegmentedAddressSpace space, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Processing entry point...");

		OldDOSHeader header = mz.getHeader();

		int ipValue = Short.toUnsignedInt(header.e_ip());

		Address addr = space.getAddress((INITIAL_SEGMENT_VAL + header.e_cs() & 0xffff), ipValue);
		SymbolTable symbolTable = program.getSymbolTable();

		try {
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(addr);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Failed to process entry point");
		}
	}

	private void processRegisters(Program program, MzExecutable mz, MessageLog log,
			TaskMonitor monitor) {
		monitor.setMessage("Processing registers...");

		Symbol entry = SymbolUtilities.getLabelOrFunctionSymbol(program, ENTRY_NAME,
			err -> log.appendMsg(err));
		if (entry == null) {
			return;
		}

		boolean shouldSetDS = false;
		long dsValue = 0;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isExecute()) {
				SegmentedAddress blockAddr = (SegmentedAddress) block.getStart();
				dsValue = Integer.toUnsignedLong(blockAddr.getSegment());
				shouldSetDS = true;
				break;
			}
		}

		OldDOSHeader header = mz.getHeader();
		ProgramContext context = program.getProgramContext();
		Register ss = context.getRegister("ss");
		Register sp = context.getRegister("sp");
		Register ds = context.getRegister("ds");
		Register cs = context.getRegister("cs");

		try {
			context.setValue(sp, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Short.toUnsignedLong(header.e_sp())));
			context.setValue(ss, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(
					Integer.toUnsignedLong((header.e_ss() + INITIAL_SEGMENT_VAL) & 0xffff)));



			for (MemoryBlock block : program.getMemory().getBlocks()) {
				Address start = block.getStart();
				Address end = block.getEnd();
				
				if (!(start.getAddressSpace() instanceof SegmentedAddressSpace)) {
					continue;
				}
				
				BigInteger csValue = BigInteger.valueOf(
						Integer.toUnsignedLong(((SegmentedAddress) start).getSegment()));
				
				context.setValue(cs, start, end, csValue);
				if (shouldSetDS) {
					context.setValue(ds, start, end, BigInteger.valueOf(dsValue));
				}
			}
		}
		catch (ContextChangeException e) {
			// ignore since segment registers should never cause this error
		}
	}

	/**
	 * Gets a {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the image
	 * is loaded into memory
	 * 
	 * @param space The address space
	 * @param mz The {@link MzExecutable}
	 * @param monitor A monitor
	 * @return A {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the 
	 *   image is loaded into memory
	 * @throws CancelledException If the action was cancelled
	 */
	private Set<RelocationFixup> getRelocationFixups(SegmentedAddressSpace space,
			MzExecutable mz, MessageLog log, TaskMonitor monitor) throws CancelledException {
		final byte CALLF = (byte) 0x9a;
		final byte JMPF = (byte) 0xea;

		Set<RelocationFixup> fixups = new HashSet<>();

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();

		for (MzRelocation relocation : mz.getRelocations()) {
			monitor.checkCanceled();

			int seg = relocation.getSegment();
			int off = relocation.getOffset();

			int relativeSegment = (seg - Short.toUnsignedInt(header.e_cs())) & 0xffff;
			int relocationFileOffset = addressToFileOffset(relativeSegment, off, header);
			SegmentedAddress relocationAddress =
				space.getAddress((relativeSegment + INITIAL_SEGMENT_VAL) & 0xffff, off);

			try {
				int relativeTargetSegment = Short.toUnsignedInt(reader.readShort(relocationFileOffset));
				int targetSegment = (relativeTargetSegment + INITIAL_SEGMENT_VAL) & 0xffff;
				int targetOffset;
				int targetFileOffset;
				boolean isCode;

				byte value = reader.readByte(relocationFileOffset - 3);
				if (value == CALLF || value == JMPF) {
					targetOffset = Short.toUnsignedInt(reader.readShort(relocationFileOffset - 2));
					targetFileOffset =
						addressToFileOffset(relativeTargetSegment, targetOffset, header);
					isCode = true;
				}
				else {
					boolean isMov = value == 0x6; // really 2-byte move: C7 06
					targetOffset = 0;
					targetFileOffset =
						addressToFileOffset(relativeTargetSegment, targetOffset, header);
					isCode = isMov || targetSegment == INITIAL_SEGMENT_VAL;
				}

				fixups.add(new RelocationFixup(relocationFileOffset,
					space.getAddress(targetSegment, targetOffset), targetFileOffset, isCode));
			}
			catch (AddressOutOfBoundsException | IOException e) {
				log.appendMsg(String.format("Failed to process relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}
		}

		return fixups;
	}

	/**
	 * Converts a segmented address to a file offset
	 * 
	 * @param segment The segment
	 * @param offset The offset
	 * @param header The header
	 * @return The segmented addresses converted to a file offset
	 */
	private int addressToFileOffset(int segment, int offset, OldDOSHeader header) {
		return (segment << 4) + offset + paragraphsToBytes(header.e_cparhdr());
	}

	/**
	 * Gets the size of the MZ file in bytes
	 * 
	 * @param header The header
	 * @return The size of the MZ file in bytes
	 */
	private int fileSize(OldDOSHeader header) {
		return pagesToBytes(header.e_cp() - 1) + header.e_cblp();
	}

	/**
	 * Converts paragraphs to bytes.  There are 16 bytes in a paragraph.
	 * 
	 * @param paragraphs The number of paragraphs
	 * @return The number of bytes in the given number of paragraphs
	 */
	private int paragraphsToBytes(int paragraphs) {
		return paragraphs << 4;
	}

	/**
	 * Converts pages to bytes.  There are 512 bytes in a paragraph.
	 * 
	 * @param pages The number of pages
	 * @return The number of bytes in the given number of pages
	 */
	private int pagesToBytes(int pages) {
		return pages << 9;
	}
}
