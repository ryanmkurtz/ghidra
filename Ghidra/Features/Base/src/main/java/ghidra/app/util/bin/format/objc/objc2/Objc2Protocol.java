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
import ghidra.app.util.bin.format.objc.*;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;

public class Objc2Protocol implements StructConverter {
	public final static String NAME = "protocol_t";

	private ObjcState _state;
	private long _index;

	private long isa;
	private String name;
	private Objc2ProtocolList protocols;
	private Objc2MethodList instanceMethods;
	private Objc2MethodList classMethods;

	private Objc2MethodList optionalInstanceMethods;
	private Objc2MethodList optionalClassMethods;
	private Objc2PropertyList instanceProperties;
	private long unknown0;
	private long unknown1;

	public Objc2Protocol(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		isa = ObjcUtils.readNextIndex(reader, state.is32bit);//TODO
		readName(reader);
		readProtocols(reader);
		readInstanceMethods(reader);
		readClassMethods(reader);
		readOptionalInstanceMethods(reader);
		readOptionalClassMethods(reader);
		readInstanceProperties(reader);

		if (state.is32bit) {
			unknown0 = reader.readNextUnsignedInt();
			unknown1 = reader.readNextUnsignedInt();
		}
		else {
			unknown0 = reader.readNextLong();
			unknown1 = reader.readNextLong();
		}
	}

	public long getIsa() {
		return isa;
	}

	public String getName() {
		return name;
	}

	public Objc2ProtocolList getProtocols() {
		return protocols;
	}

	public Objc2MethodList getInstanceMethods() {
		return instanceMethods;
	}

	public Objc2MethodList getClassMethods() {
		return classMethods;
	}

	public Objc2MethodList getOptionalInstanceMethods() {
		return optionalInstanceMethods;
	}

	public Objc2MethodList getOptionalClassMethods() {
		return optionalClassMethods;
	}

	public Objc2PropertyList getInstanceProperties() {
		return instanceProperties;
	}

	public long getUnknown0() {
		return unknown0;
	}

	public long getUnknown1() {
		return unknown1;
	}

	public long getIndex() {
		return _index;
	}

	private void readProtocols(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			protocols = new Objc2ProtocolList(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readName(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			name = reader.readAsciiString(index);
		}
	}

	private void readInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceMethods =
				new Objc2MethodList(_state, reader, ObjcMethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readClassMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			classMethods = new Objc2MethodList(_state, reader, ObjcMethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalInstanceMethods =
				new Objc2MethodList(_state, reader, ObjcMethodType.INSTANCE);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readOptionalClassMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			optionalClassMethods =
				new Objc2MethodList(_state, reader, ObjcMethodType.CLASS);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceProperties(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceProperties = new Objc2PropertyList(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		if (_state.is32bit) {
			struct.add(DWORD, "isa", null);
		}
		else {
			struct.add(QWORD, "isa", null);
		}

		struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);
		struct.add(new PointerDataType(Objc2ProtocolList.toGenericDataType(_state)),
			_state.pointerSize, "protocols", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),
			_state.pointerSize, "instanceMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),
			_state.pointerSize, "classMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),
			_state.pointerSize, "optionalInstanceMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),
			_state.pointerSize, "optionalClassMethods", null);
		struct.add(new PointerDataType(Objc2PropertyList.toGenericDataType()),
			_state.pointerSize, "instanceProperties", null);

		if (_state.is32bit) {
			struct.add(DWORD, "unknown0", null);
			struct.add(DWORD, "unknown1", null);
		}
		else {
			struct.add(QWORD, "unknown0", null);
			struct.add(QWORD, "unknown1", null);
		}

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) throws Exception {
		Address address = ObjcUtils.toAddress(_state.program, getIndex());
		try {
			ObjcUtils.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {
		}

		try {
			Namespace protocolNamespace =
				ObjcUtils.createNamespace(_state.program,
					Objc1Constants.NAMESPACE, Objc2Protocol.NAME);
			ObjcUtils.createSymbol(_state.program, protocolNamespace, getName(),
				address);
		}
		catch (Exception e) {
		}

		if (protocols != null) {
			protocols.applyTo(namespace);
		}
		if (instanceMethods != null) {
			instanceMethods.applyTo(namespace);
		}
		if (classMethods != null) {
			classMethods.applyTo(namespace);
		}
		if (optionalInstanceMethods != null) {
			optionalInstanceMethods.applyTo(namespace);
		}
		if (optionalClassMethods != null) {
			optionalClassMethods.applyTo(namespace);
		}
		if (instanceProperties != null) {
			instanceProperties.applyTo(namespace);
		}
	}
}
