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
package ghidra.app.util.bin.format.objc;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;

public abstract class ObjcMethodList implements StructConverter {
	private String _className;
	protected ObjcState _state;
	protected long _index = -1;

	protected List<ObjcMethod> methods = new ArrayList<ObjcMethod>();

	protected ObjcMethodList(ObjcState state, BinaryReader reader,
			String className) {
		this._state = state;
		this._index = reader.getPointerIndex();
		this._className = className;
	}

	public List<ObjcMethod> getMethods() {
		return methods;
	}

	public void applyTo(Namespace namespace) throws Exception {
		if (_index == 0) {
			return;
		}
		if (_state.beenApplied.contains(_index)) {
			return;
		}
		_state.beenApplied.add(_index);

		Address address = ObjcUtils.toAddress(_state.program, _index);
		DataType dt = toDataType();
		try {
			ObjcUtils.applyData(_state.program, dt, address);
		}
		catch (Exception e) {
			Msg.warn(this, "Could not create " + dt.getName() + " @" + address);
		}

		try {
			//creates a symbol on the method list data structure
			Namespace methodListNamespace = ObjcUtils.createNamespace(_state.program,
				Objc1Constants.NAMESPACE, _className);
			ObjcUtils.createSymbol(_state.program, methodListNamespace,
				namespace.getName(), address);
		}
		catch (Exception e) {
		}

		for (ObjcMethod method : getMethods()) {
			method.applyTo(namespace);
		}
	}

}
