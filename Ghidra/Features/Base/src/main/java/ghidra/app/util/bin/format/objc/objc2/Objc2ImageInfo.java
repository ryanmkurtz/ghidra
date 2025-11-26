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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objc.ObjcState;
import ghidra.app.util.bin.format.objc.ObjcUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Objc2ImageInfo implements StructConverter {
	public final static int OBJC_IMAGE_IS_REPLACEMENT = 1 << 0;
	public final static int OBJC_IMAGE_SUPPORTS_GC    = 1 << 1;
	public final static int OBJC_IMAGE_REQUIRES_GC    = 1 << 2;

	private ObjcState _state;
	private long _index;

	private int version;
	private int flags;

	public Objc2ImageInfo(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		version   = reader.readNextInt();
		flags     = reader.readNextInt();
	}

	public int getVersion() {
		return version;
	}

	public int getFlags() {
		return flags;
	}

	public boolean isReplacement() {
		return (flags & OBJC_IMAGE_IS_REPLACEMENT) != 0;
	}

	public boolean isSupportsGarbageCollection() {
		return (flags & OBJC_IMAGE_SUPPORTS_GC) != 0;
	}

	public boolean isRequiresGarbageCollection() {
		return (flags & OBJC_IMAGE_REQUIRES_GC) != 0;
	}

	public long getIndex() {
		return _index;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("objc_image_info", 0);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "flags", null);
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo() throws Exception {
		Address address = ObjcUtils.toAddress(_state.program, getIndex());
		ObjcUtils.applyData(_state.program, toDataType(), address);

	}
}
