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

public class Objc2Category implements StructConverter {
	public final static String NAME = "category_t";

	private ObjcState _state;
	private long _index;

	private String name;
	private Objc2Class cls;
	private Objc2MethodList instanceMethods;
	private Objc2MethodList classMethods;
	private Objc2ProtocolList protocols;
	private Objc2PropertyList instanceProperties;

	public Objc2Category(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		readName(reader);
		readClass(reader);
		if (cls != null && cls.getISA() != null) {
			readInstanceMethods(reader);
			readClassMethods(reader);
			readProtocols(reader);
			readInstanceProperties(reader);
		}
	}

	public long getIndex() {
		return _index;
	}

	public String getName() {
		return name;
	}

	public Objc2Class getCls() {
		return cls;
	}

	public Objc2MethodList getInstanceMethods() {
		return instanceMethods;
	}

	public Objc2MethodList getClassMethods() {
		return classMethods;
	}

	public Objc2ProtocolList getProtocols() {
		return protocols;
	}

	public Objc2PropertyList getInstanceProperties() {
		return instanceProperties;
	}

	private void readName(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			name = reader.readAsciiString(index);
		}
	}

	private void readClass(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);

		if (_state.classIndexMap.containsKey(index)) {
			cls = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			cls = new Objc2Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readInstanceMethods(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			instanceMethods = new Objc2MethodList(_state, reader, ObjcMethodType.INSTANCE);
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

	private void readProtocols(BinaryReader reader) throws IOException {
		long index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			protocols = new Objc2ProtocolList(_state, reader);
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
		StringBuffer buffer = new StringBuffer();
		buffer.append(NAME);

		if (cls == null) {
			buffer.append("<no_class>");
		}

		Structure struct = new StructureDataType(buffer.toString(), 0);

		struct.add(new PointerDataType(STRING), _state.pointerSize, "name", null);

		if (cls == null) {
			struct.add(new PointerDataType(VOID), _state.pointerSize, "cls", null);
		}
		else {
			struct.add(new PointerDataType(cls.toDataType()), _state.pointerSize, "cls", null);
		}

		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),         _state.pointerSize, "instanceMethods", null);
		struct.add(new PointerDataType(Objc2MethodList.toGenericDataType()),         _state.pointerSize, "classMethods", null);
		struct.add(new PointerDataType(Objc2ProtocolList.toGenericDataType(_state)), _state.pointerSize, "protocols", null);
		struct.add(new PointerDataType(Objc2PropertyList.toGenericDataType()),       _state.pointerSize, "instanceProperties", null);

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo() throws Exception {
		Address address = ObjcUtils.toAddress(_state.program, getIndex());

		try {
			ObjcUtils.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {}

		try {
			Namespace categoryNamespace = ObjcUtils.createNamespace(_state.program, Objc1Constants.NAMESPACE, Objc2Category.NAME);
			ObjcUtils.createSymbol(_state.program, categoryNamespace, getName(), address);
		}
		catch (Exception e) {}

		String string = null;
		try {
			string = cls.getData().getName()+'_'+name+'_';
		}
		catch (Exception e) {
			string = name;
		}
		Namespace namespace = ObjcUtils.createNamespace(_state.program, Objc1Constants.NAMESPACE, "Categories", string);

		if (cls != null) {
			cls.applyTo();
		}
		if (instanceMethods != null) {
			instanceMethods.applyTo(namespace);
		}
		if (classMethods != null) {
			classMethods.applyTo(namespace);
		}
		if (protocols != null) {
			protocols.applyTo(namespace);
		}
		if (instanceProperties != null) {
			instanceProperties.applyTo(namespace);
		}
	}
}
