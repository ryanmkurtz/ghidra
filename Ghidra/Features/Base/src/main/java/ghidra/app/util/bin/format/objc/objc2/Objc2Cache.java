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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.DuplicateNameException;

public class Objc2Cache implements StructConverter {
	private ObjcState _state;

	private long cache;

	public Objc2Cache(ObjcState state, BinaryReader reader) throws IOException {
		this._state = state;
		cache = ObjcUtils.readNextIndex(reader, state.is32bit);
	}

	public long getCache() {
		return cache;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return new TypedefDataType("Cache", _state.is32bit ? DWORD : QWORD);
	}

	public void applyTo() throws Exception {
		// do nothing
	}
}
