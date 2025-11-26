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
import ghidra.program.model.listing.Data;
import ghidra.util.exception.DuplicateNameException;

public class Objc2MessageReference implements StructConverter {
	public static final String NAME = "message_ref";

	public static int SIZEOF(ObjcState state) {
		return 2 * state.pointerSize;
	}

	private ObjcState _state;
	private long _index;

	private long implementation;
	private String selector;

	public Objc2MessageReference(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		if (state.is32bit) {
			implementation = reader.readNextUnsignedInt();
		}
		else {
			implementation = reader.readNextLong();
		}

		long selectorIndex = ObjcUtils.readNextIndex(reader, state.is32bit);
		if (selectorIndex != 0) {
			selector = reader.readAsciiString(selectorIndex);
		}
	}

	public long getImplementation() {
		return implementation;
	}

	public String getSelector() {
		return selector;
	}

	public void applyTo() throws Exception {
		Address address = ObjcUtils.toAddress(_state.program, _index);
		DataType dt = toDataType();
		Data messageRefData = _state.program.getListing().createData(address, dt);
		Data selData = messageRefData.getComponent(1);
		Object selAddress = selData.getValue();
		Data selStringData = _state.program.getListing().getDataAt((Address) selAddress);
		Object selString = selStringData.getValue();
		ObjcUtils.createSymbol(_state.program, null, selString + "_" + Objc2MessageReference.NAME,
			address);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(new PointerDataType(VOID),  _state.pointerSize, "imp", null);
		struct.add(new PointerDataType(ASCII), _state.pointerSize, "sel", null);
		return struct;
	}
}

