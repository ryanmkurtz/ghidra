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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objc.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class Objc1Class implements StructConverter {
	public final static String NAME = "objc_class";
	public static final long SIZEOF = 0x30;

	private ObjcState _state;
	private long _index;

	private Objc1MetaClass isa;
	private String super_class;
	private String name;
	private int version;
	private int info;
	private int instance_size;
	private Objc1InstanceVariableList variable_list;
	private Objc1MethodList method_list;
	private int cache;
	private Objc1ProtocolList protocols;
	private int unknown0;
	private int unknown1;

	public Objc1Class(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa = new Objc1MetaClass(state, reader.clone(reader.readNextInt()));
		super_class = ObjcUtils.dereferenceAsciiString(reader, state.is32bit);
		name = reader.readAsciiString(reader.readNextInt());
		version = reader.readNextInt();
		info = reader.readNextInt();
		instance_size = reader.readNextInt();
		variable_list =
			new Objc1InstanceVariableList(state, reader.clone(reader.readNextInt()));
		method_list =
			new Objc1MethodList(state, reader.clone(reader.readNextInt()),
				ObjcMethodType.INSTANCE);
		cache = reader.readNextInt();
		protocols = new Objc1ProtocolList(state, reader.clone(reader.readNextInt()));
		unknown0 = reader.readNextInt();
		unknown1 = reader.readNextInt();
	}

	public Objc1MetaClass getISA() {
		return isa;
	}

	public String getSuperClass() {
		return super_class;
	}

	public String getName() {
		return name;
	}

	public int getVersion() {
		return version;
	}

	public int getInfo() {
		return info;
	}

	public int getInstanceSize() {
		return instance_size;
	}

	public Objc1InstanceVariableList getInstanceVariableList() {
		return variable_list;
	}

	public Objc1MethodList getMethodList() {
		return method_list;
	}

	public int getCache() {
		return cache;
	}

	public Objc1ProtocolList getProtocols() {
		return protocols;
	}

	public int getUnknown0() {
		return unknown0;
	}

	public int getUnknown1() {
		return unknown1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.setCategoryPath(Objc1Constants.CATEGORY_PATH);
		struct.add(PointerDataType.getPointer(isa.toDataType(), _state.pointerSize), "isa", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "super_class", null);
		struct.add(PointerDataType.getPointer(ASCII, _state.pointerSize), "name", null);
		struct.add(DWORD, "version", null);
		struct.add(DWORD, "info", null);
		struct.add(DWORD, "instance_size", null);
		struct.add(PointerDataType.getPointer(Objc1InstanceVariableList.toGenericDataType(),
			_state.pointerSize), "instance_vars", null);
		struct.add(PointerDataType.getPointer(Objc1MethodList.toGenericDataType(_state),
			_state.pointerSize), "method_lists", null);
		struct.add(DWORD, "cache", null);
		struct.add(PointerDataType.getPointer(Objc1ProtocolList.toGenericDataType(_state),
			_state.pointerSize), "protocols", null);
		struct.add(DWORD, "unknown0", null);
		struct.add(DWORD, "unknown1", null);
		return struct;
	}

	public void applyTo() throws Exception {
		Address address =
			_state.program.getAddressFactory().getDefaultAddressSpace().getAddress(_index);
		DataType dt = toDataType();
		_state.program.getListing().clearCodeUnits(address, address.add(dt.getLength() - 1), false);
		_state.program.getListing().createData(address, dt);
		_state.program.getSymbolTable().createLabel(address, "objc_class_" + name,
			SourceType.ANALYSIS);

		Namespace namespace = ObjcUtils.getClassNamespace(_state.program, null, name);

		isa.applyTo();
		variable_list.applyTo();
		method_list.applyTo(namespace);

		//don't do protocols here... they are applied independent
	}
}
