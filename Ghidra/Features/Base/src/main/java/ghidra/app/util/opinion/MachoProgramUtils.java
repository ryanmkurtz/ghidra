package ghidra.app.util.opinion;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class MachoProgramUtils {

	public static Address getNextAvailableAddress(Program program) {
		Address maxAddress = null;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isOverlay()) {
				continue;
			}
			if (maxAddress == null || block.getEnd().compareTo(maxAddress) > 0) {
				maxAddress = block.getEnd();
			}
		}
		if (maxAddress == null) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
		}
		long maxAddr = maxAddress.getOffset();
		long remainder = maxAddr % 0x1000;
		return maxAddress.getNewAddress(maxAddr + 0x1000 - remainder);
	}

	public static Address addExternalBlock(Program program, long size, MessageLog log)
			throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock externalBlock = mem.getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
		Address ret;
		if (externalBlock != null) {
			ret = externalBlock.getEnd().add(1);
			MemoryBlock newBlock = mem.createBlock(externalBlock, "REEXPORTS", ret, size);
			mem.join(externalBlock, newBlock);
			//joinedBlock.setName(MemoryBlock.EXTERNAL_BLOCK_NAME);
		}
		else {
			ret = MachoProgramUtils.getNextAvailableAddress(program);
			externalBlock =
				mem.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, ret, size, false);
			externalBlock.setWrite(true);
			externalBlock.setArtificial(true);
			externalBlock.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");
		}
		return ret;
	}
}
