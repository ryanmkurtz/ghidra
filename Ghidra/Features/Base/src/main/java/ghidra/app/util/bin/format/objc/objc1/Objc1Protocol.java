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
package ghidra.app.util.bin.format.objc.objc1;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Objc1Protocol implements StructConverter {
	public final static String NAME = "objc_protocol";
	public final static int SIZEOF = 20;

	private ObjcState _state;
	private long _index;

	private int isa;
	private String name;
	private Objc1ProtocolList protocolList;
	private Objc1ProtocolMethodList instanceMethods;
	private Objc1ProtocolMethodList classMethods;

	public Objc1Protocol(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa             = reader.readNextInt();
		name            = ObjcUtils.dereferenceAsciiString(reader, state.is32bit);
		protocolList    = new Objc1ProtocolList(state, reader.clone(reader.readNextInt()));
		instanceMethods = new Objc1ProtocolMethodList(state, reader.clone(reader.readNextInt()), ObjcMethodType.INSTANCE);
		classMethods    = new Objc1ProtocolMethodList(state, reader.clone(reader.readNextInt()), ObjcMethodType.CLASS);
	}

	public int getIsa() {
		return isa;
	}

	public String getName() {
		return name;
	}

	public Objc1ProtocolList getProtocolList() {
		return protocolList;
	}

	public Objc1ProtocolMethodList getInstanceMethods() {
		return instanceMethods;
	}

	public Objc1ProtocolMethodList getClassMethods() {
		return classMethods;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(DWORD, "isa", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolList.toGenericDataType(_state), _state.pointerSize), "protocolList", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolMethodList.toGenericDataType(_state), _state.pointerSize), "instanceMethods", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolMethodList.toGenericDataType(_state), _state.pointerSize), "classMethods", null);
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = _state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength()-1), false);
		_state.program.getListing().createData(address, dt);

		protocolList.applyTo();
		instanceMethods.applyTo();
		classMethods.applyTo();
	}

}
