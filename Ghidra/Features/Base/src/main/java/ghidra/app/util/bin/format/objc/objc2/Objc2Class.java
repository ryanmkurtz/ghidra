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
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objc.ObjcState;
import ghidra.app.util.bin.format.objc.ObjcUtils;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;

public class Objc2Class implements StructConverter {
	public final static String NAME = "class_t";

	private ObjcState _state;
	private long _index;

	private Objc2Class isa;
	private Objc2Class superclass;
	private Objc2Cache cache;
	private Objc2Implementation vtable;
	private Objc2ClassRW data; // class_rw_t * plus custom rr/alloc flags

	public Objc2Class(ObjcState state, BinaryReader reader) {
		this._state = state;
		this._index = reader.getPointerIndex();

		state.classIndexMap.put(_index, this);
		
		// Some class references point to a GOT entry. These aren't real class structures, so don't 
		// parse them.
		AddressSpace space = _state.program.getAddressFactory().getDefaultAddressSpace();
		Address addr = space.getAddress(_index);
		Symbol symbol = _state.program.getSymbolTable().getPrimarySymbol(addr);
		if (symbol != null && symbol.getParentNamespace().getName().equals(SectionNames.SECT_GOT)) {
			return;
		}

		try {
			readISA(reader);
			readSuperClass(reader);
			readCache(reader);
			readVTable(reader);
			readData(reader);
		}
		catch (IOException ioe) {
			// Couldn't read something, usually a metaclass pointing to an uninitialized section since
			// runtime 2.0 got rid of the metaclass type.
		}
	}

	@Override
	public boolean equals(Object that) {
		if (that instanceof Objc2Class) {
			return this._index == ((Objc2Class) that)._index;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (int) _index;
	}

	public Objc2Class getISA() {
		return isa;
	}

	public Objc2Class getSuperClass() {
		return superclass;
	}

	public Objc2Cache getCache() {
		return cache;
	}

	public Objc2Implementation getVTable() {
		return vtable;
	}

	public Objc2ClassRW getData() {
		return data;
	}

	public long getIndex() {
		return _index;
	}

	private void readData(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		// Fix pointer by applying Swift FAST_DATA_MASK (see objc-runtime-new.h for details)
		index &= _state.is64bit ? ~0x7L : ~0x3L;

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			data = new Objc2ClassRW(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readVTable(BinaryReader reader) {
		try {
			vtable = new Objc2Implementation(_state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readCache(BinaryReader reader) {
		try {
			cache = new Objc2Cache(_state, reader);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
		}
	}

	private void readSuperClass(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (_state.classIndexMap.containsKey(index)) {
			superclass = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			superclass = new Objc2Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	private void readISA(BinaryReader reader) throws IOException {
		long index = 0;
		try {
			index = ObjcUtils.readNextIndex(reader, _state.is32bit);
		}
		catch (IOException ioe) {
			//Trying to read uninitialized memory
			return;
		}

		if (_state.classIndexMap.containsKey(index)) {
			isa = _state.classIndexMap.get(index);
			return;
		}

		if (index != 0 && reader.isValidIndex(index)) {
			long originalIndex = reader.getPointerIndex();
			reader.setPointerIndex(index);
			isa = new Objc2Class(_state, reader);
			reader.setPointerIndex(originalIndex);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME, 0);

		struct.add(new PointerDataType(struct), _state.pointerSize, "isa", null);
		struct.add(new PointerDataType(struct), _state.pointerSize, "superclass", null);
		struct.add(cache.toDataType(), "cache", null);
		struct.add(vtable.toDataType(), "vtable", null);

		if (data == null) {
			Objc2ClassRW fakeData = new Objc2ClassRW();
			struct.add(new PointerDataType(fakeData.toDataType()), _state.pointerSize, "data", null);
		}
		else {
			struct.add(new PointerDataType(data.toDataType()), _state.pointerSize, "data", null);
		}

		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo() throws Exception {
		if (_state.beenApplied.contains(_index)) {//handle circular references
			return;
		}
		_state.beenApplied.add(_index);

		Address address = ObjcUtils.toAddress(_state.program, getIndex());
		try {
			ObjcUtils.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {
		}

		try {
			Namespace namespace =
				ObjcUtils.createNamespace(_state.program,
					Objc1Constants.NAMESPACE, Objc2Class.NAME);
			ObjcUtils.createSymbol(_state.program, namespace, data.getName(), address);
		}
		catch (Exception e) {
		}

		if (isa != null) {
			isa.applyTo();
		}
		if (superclass != null) {
			superclass.applyTo();
		}
		if (cache != null) {
			cache.applyTo();
		}
		if (vtable != null) {
			vtable.applyTo();
		}
		if (data != null) {
			data.applyTo();
		}
	}
}
