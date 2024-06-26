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
package ghidra.app.plugin.core.searchmem;

import docking.widgets.table.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.search.memory.*;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

public class MemSearchTableModel extends AddressBasedTableModel<MemSearchResult> {

	private SearchInfo searchInfo;
	private ProgramSelection selection;
	private Address startAddress;
	private MemorySearchAlgorithm algorithm;

	MemSearchTableModel(ServiceProvider serviceProvider, Program program, SearchInfo searchInfo,
			Address searchStartAddress, ProgramSelection programSelection) {
		super("Memory Search", serviceProvider, program, null, true);
		this.searchInfo = searchInfo;
		this.startAddress = searchStartAddress;
		this.selection = programSelection;
	}

	public boolean isSortedOnAddress() {
		TableSortState sortState = getTableSortState();
		if (sortState.isUnsorted()) {
			return false;
		}

		ColumnSortState primaryState = sortState.getAllSortStates().get(0);
		DynamicTableColumn<MemSearchResult, ?, ?> column =
			getColumn(primaryState.getColumnModelIndex());
		String name = column.getColumnName();
		if (AddressTableColumn.NAME.equals(name)) {
			return true;
		}
		return false;
	}

	@Override
	protected void doLoad(Accumulator<MemSearchResult> accumulator, TaskMonitor monitor)
			throws CancelledException {
		algorithm = searchInfo.createSearchAlgorithm(getProgram(), startAddress, selection);
		algorithm.search(accumulator, monitor);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		Program p = getProgram();
		if (p == null) {
			return null; // we've been disposed
		}

		ProgramLocation loc = super.getProgramLocation(row, column);
		if (loc != null && p.getMemory().contains(loc.getByteAddress())) {
			return new BytesFieldLocation(p, loc.getByteAddress());
		}
		return null;
	}

	@Override
	public Address getAddress(int row) {
		MemSearchResult result = getRowObject(row);
		return result.getAddress();
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet addressSet = new AddressSet();
		for (int row : rows) {
			MemSearchResult result = getRowObject(row);
			int addOn = result.getLength() - 1;
			Address minAddr = getAddress(row);
			Address maxAddr = minAddr;
			try {
				maxAddr = minAddr.addNoWrap(addOn);
				addressSet.addRange(minAddr, maxAddr);
			}
			catch (AddressOverflowException e) {
				// I guess we don't care--not sure why this is undocumented :(
			}
		}
		return new ProgramSelection(addressSet);
	}
}
