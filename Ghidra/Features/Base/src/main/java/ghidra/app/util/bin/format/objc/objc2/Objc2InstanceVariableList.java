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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objc.ObjcState;
import ghidra.app.util.bin.format.objc.ObjcUtils;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.DuplicateNameException;

public class Objc2InstanceVariableList implements StructConverter {
	public final static String NAME = "ivar_list_t";

	private ObjcState _state;
	private long _index;

	private int entsize;
	private int count;
	private List<Objc2InstanceVariable> ivars = new ArrayList<Objc2InstanceVariable>();

	public Objc2InstanceVariableList(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		this._index = reader.getPointerIndex();

		entsize = reader.readNextInt();
		count   = reader.readNextInt();

		for (int i = 0 ; i < count ; ++i) {
			ivars.add( new Objc2InstanceVariable(state, reader) );
		}
	}

	public long getEntsize() {
		return entsize;
	}

	public long getCount() {
		return count;
	}

	public List<Objc2InstanceVariable> getIvars() {
		return ivars;
	}

	public long getIndex() {
		return _index;
	}

	public static DataType toGenericDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "entsize", null);
		struct.add(DWORD,   "count", null);
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(NAME+'_'+count+'_', 0);

		struct.add(DWORD, "entsize", null);
		struct.add(DWORD,   "count", null);

		for (int i = 0 ; i < ivars.size() ; ++i) {
			struct.add(ivars.get(i).toDataType(), "var"+i, null);
		}
		struct.setCategoryPath(Objc2Constants.CATEGORY_PATH);
		return struct;
	}

	public void applyTo(Namespace namespace) throws Exception {
		Address address = ObjcUtils.toAddress(_state.program, getIndex());
		try {
			ObjcUtils.applyData(_state.program, toDataType(), address);
		}
		catch (Exception e) {}

		try {
			Namespace instanceVariableNamespace = ObjcUtils.createNamespace(_state.program, Objc1Constants.NAMESPACE, Objc2InstanceVariableList.NAME);
			ObjcUtils.createSymbol(_state.program, instanceVariableNamespace, namespace.getName(), address);
		}
		catch (Exception e) {}

		for (Objc2InstanceVariable ivar : getIvars()) {
			ivar.applyTo(namespace);
		}
	}
}
