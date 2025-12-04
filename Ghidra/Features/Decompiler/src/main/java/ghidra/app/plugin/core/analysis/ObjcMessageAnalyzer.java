package ghidra.app.plugin.core.analysis;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objc.ObjcUtils;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.app.util.bin.format.objc.objc2.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Analyzes {@code _objc_msgSend} information 
 */
public class ObjcMessageAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Objective-C Message Analyzer";
	private static final String DESCRIPTION = "Analyzes _objc_msgSend information.";

	private static final DataTypePath ID_PATH =
		new DataTypePath(Objc2Constants.CATEGORY_PATH, "ID");
	private static final DataTypePath SEL_PATH =
		new DataTypePath(Objc2Constants.CATEGORY_PATH, "SEL");

	private final static String STUB_NAMESPACE = "objc_stub";
	private final int MAX_RECURSION_DEPTH = 10;

	private Objc2TypeMetadata typeMetadata;
	private Map<String, List<Objc2Class>> classMap;

	private record Message(String receiver, String selector, PcodeOpAST op, boolean isStret,
			Address addr) {}

	public ObjcMessageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_ANALYSIS.before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Objc2Constants.isObjectiveC2(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		set = set.intersect(program.getMemory().getLoadedAndInitializedAddressSet());

		try {
			if (typeMetadata == null) {
				typeMetadata = new Objc2TypeMetadata(program, monitor, log);
				classMap = typeMetadata.getClasses()
						.stream()
						.collect(Collectors.groupingBy(e -> e.getData().getName()));
			}
		}
		catch (IOException e) {
			log.appendMsg("Failed to parse Objective-C type metadata: " + e.getMessage());
			return false;
		}

		// Fix __objc_msgSend() function signatures
		fixMsgSendSignatures(program, monitor, log);

		// Set up a standalone decompiler for later use
		DecompileConfigurer configurer = d -> setupDecompiler(program, d);
		DecompInterface decompiler = new DecompInterface();
		configurer.configure(decompiler);
		decompiler.openProgram(program);

		// Use parallel decompiler to override _objc_msgSend() calls to their proper destinations
		DecompilerCallback<Void> callback =
			new DecompilerCallback<>(program, configurer) {
				@Override
				public Void process(DecompileResults results, TaskMonitor m) throws Exception {
					fixMsgSendCalls(program, results.getHighFunction(), decompiler, log, monitor);
					return null;
				}
			};
		try {
			ParallelDecompiler.decompileFunctions(callback, getFunctionsInTextSection(program, set),
				monitor);
		}
		catch (Exception e) {
			if (e.getCause() instanceof CancelledException ce) {
				throw ce;
			}
			log.appendException(e);
		}
		finally {
			callback.dispose();
			decompiler.closeProgram();
		}
		return true;
	}

	@Override
	public void analysisEnded(Program program) {
		if (typeMetadata != null) {
			typeMetadata.close();
			typeMetadata = null;
		}
	}

	private void fixMsgSendSignatures(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// Get the data types that we'll need to use
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		DataType ptr = program.getDefaultPointerSize() == 8 ? Pointer64DataType.dataType
				: Pointer32DataType.dataType;
		DataType id = dtm.getDataType(ID_PATH);
		DataType sel = dtm.getDataType(SEL_PATH);
		if (id == null || sel == null) {
			log.appendMsg("%s or %s data types were not found".formatted(ID_PATH, SEL_PATH));
			return;
		}

		for (Function func : program.getFunctionManager().getFunctions(program.getMemory(), true)) {
			monitor.checkCancelled();

			String name = func.getName();
			Namespace global = program.getGlobalNamespace();
			boolean isStub = isObjcMsgSendStub(program, func.getEntryPoint());

			if (!name.startsWith(Objc1Constants.OBJC_MSG_SEND) && !isStub) {
				continue;
			}

			try {
				// Set up the parameter list
				ArrayList<Parameter> params = new ArrayList<>();
				if (name.endsWith("stret")) {
					params.add(new ParameterImpl("stretAddr", ptr, program));
				}
				params.add(
					new ParameterImpl(name.endsWith("Super") ? "super" : "self", id, program));
				if (!isStub) {
					params.add(new ParameterImpl("op", sel, program));
				}

				// Set up the return value
				Variable returnVar = new ReturnParameterImpl(id, program);

				// Set up the calling convention
				String cc = CompilerSpec.CALLING_CONVENTION_unknown;
				if (isStub) {
					if (dtm.getCallingConvention(ObjcUtils.OBJC_MSGSEND_STUBS_CC) != null) {
						cc = ObjcUtils.OBJC_MSGSEND_STUBS_CC;
					}
				}

				// Update the namespace
				func.setParentNamespace(isStub ? getStubsNamespace(program) : global);

				// Update the function name
				String stubPrefix = Objc1Constants.OBJC_MSG_SEND + "$";
				if (isStub && name.startsWith(stubPrefix)) {
					func.setName(name.substring(stubPrefix.length()), SourceType.ANALYSIS);
				}

				// Update the function
				func.updateFunction(cc, returnVar, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				func.setVarArgs(true);
				func.setParentNamespace(isStub ? getStubsNamespace(program) : global);
			}
			catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				log.appendMsg("Failed to fix up function signature function for: " + func);
			}
		}
	}

	private List<Message> findMessages(Program program, HighFunction highFunction,
			DecompInterface decompiler, TaskMonitor monitor) throws CancelledException {
		List<Message> messages = new ArrayList<>();
		Function function = highFunction.getFunction();
		for (PcodeOpAST op : CollectionUtils.asIterable(highFunction.getPcodeOps())) {
			monitor.checkCancelled();

			String mnemonic = op.getMnemonic();
			if (!StringUtils.equals(mnemonic, "CALL") && !StringUtils.equals(mnemonic, "CALLIND")) {
				continue;
			}
			Varnode[] inputs = op.getInputs();
			Address callTarget = getAddressFromVarnode(program, inputs[0], 0, monitor);
			if (!isObjcMsgSendCall(program, inputs[0], callTarget, monitor)) {
				continue;
			}
			boolean isStret = isStructReturnCall(program, inputs[0], monitor);
			boolean isStub = isObjcMsgSendStub(program, callTarget);
			Varnode receiverParam = inputs[isStret ? 2 : 1];
			Varnode selectorParam = !isStub ? inputs[isStret ? 3 : 2] : null;
			String receiver =
				getNameForVarnode(program, function, receiverParam, true, false, 0, 1, monitor);
			String selector = isStub ? processStub(program, callTarget, decompiler, monitor)
					: getNameForVarnode(program, function, selectorParam, false, true, 0, 1,
						monitor);
			if (ObjectUtils.allNotNull(receiver, selector)) {
				messages.add(new Message(receiver, selector, op, isStret, callTarget));
			}
		}
		return messages;
	}

	private String processStub(Program program, Address stubAddr, DecompInterface decompiler,
			TaskMonitor monitor) throws CancelledException {
		Function func = program.getFunctionManager().getFunctionAt(stubAddr);
		DecompileResults results = decompiler.decompileFunction(func, 5, monitor);
		HighFunction highFunction = results.getHighFunction();
		if (highFunction == null) {
			return null;
		}
		List<Message> messages = findMessages(program, highFunction, decompiler, monitor);
		if (messages.isEmpty()) {
			return null;
		}
		String selector = messages.getFirst().selector;
		if (func.getName().startsWith("FUN_")) {
			try {
				func.setName(selector, SourceType.ANALYSIS);
			}
			catch (InvalidInputException | DuplicateNameException e) {
				// oh well, just cosmetic
			}
		}
		return messages.getFirst().selector;
	}

	private void fixMsgSendCalls(Program program, HighFunction highFunction,
			DecompInterface decompiler, MessageLog log, TaskMonitor monitor)
			throws CancelledException {
		if (highFunction == null) {
			return;
		}
		Function function = highFunction.getFunction();
		List<Message> messages = findMessages(program, highFunction, decompiler, monitor);
		for (Message msg : messages) {
			monitor.checkCancelled();
			List<String> parameters = new ArrayList<>();
			Varnode[] inputs = msg.op.getInputs();
			int paramStart = msg.isStret ? 4 : 3;
			for (int i = paramStart; i < inputs.length; i++) {
				String paramValue =
					getNameForVarnode(program, function, inputs[i], false, false, 0, 1, monitor);
				parameters.add(getIvarNameFromQualifiedName(paramValue));
			}
			setCommentAndReference(program, msg.receiver, msg.selector, msg.op, parameters);
		}
	}
	
	private Namespace getStubsNamespace(Program program) {
		SymbolTable symTable = program.getSymbolTable();
		Namespace global = program.getGlobalNamespace();
		Namespace namespace = symTable.getNamespace(STUB_NAMESPACE, global);
		if (namespace == null) {
			try {
				namespace = symTable.createNameSpace(global, STUB_NAMESPACE, SourceType.ANALYSIS);
			}
			catch (DuplicateNameException | InvalidInputException e) {
				return null;
			}
		}
		return namespace;
	}

	private void setCommentAndReference(Program program, String currentClassName,
			String currentMethodName, PcodeOpAST op, List<String> parameters) {
		Address objcCallAddress = op.getSeqnum().getTarget();
		objcCallAddress = getAddressInProgram(program, objcCallAddress.getOffset());
		Instruction instruction = program.getListing().getInstructionAt(objcCallAddress);

		String fullyQualifiedName = currentClassName;

		// If the target is an instance variable, we want to display the
		// variable name in the comment, but use the class type when
		// creating the reference.
		if (currentClassName.contains("::")) {
			currentClassName = getClassNameFromQualifiedName(fullyQualifiedName);
		}
		setReference(objcCallAddress, program, currentClassName, currentMethodName);

		if (instruction == null) {
			return;
		}
		if (instruction.getComment(CommentType.EOL) != null) {
			return;
		}

		currentClassName = getIvarNameFromQualifiedName(fullyQualifiedName);

		// Formatting based on whether or not the method takes parameters
		currentMethodName += currentMethodName.contains(":") ? "]" : " ]";
		String[] split = currentMethodName.split(":");
		StringBuilder builder = new StringBuilder();
		builder.append("[" + currentClassName + " " + split[0]);
		for (int i = 1; i < split.length; i++) {
			try {
				builder.append(":" + parameters.get(i - 1) + " ");
			}
			catch (Exception e) {
				// Decompiler found less params than the function should really
				// have.
				builder.append(":<<unknown>> ");
			}
			builder.append(split[i]);
		}
		builder.delete(builder.length() - 2, builder.length() - 1);
		instruction.setComment(CommentType.EOL, builder.toString());
	}

	private boolean isObjcMsgSendCall(Program program, Varnode input, Address callTarget,
			TaskMonitor monitor) throws CancelledException {
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		if (symbol == null) {
			return false;
		}
		String name = symbol.getName();
		if (name.startsWith(Objc1Constants.OBJC_MSG_SEND) ||
			name.equals(Objc1Constants.READ_UNIX2003) ||
			name.startsWith("thunk" + Objc1Constants.OBJC_MSG_SEND) ||
			name.startsWith("PTR_" + Objc1Constants.OBJC_MSG_SEND)) {
			return true;
		}
		return isObjcMsgSendStub(program, callTarget);
	}

	private boolean isObjcMsgSendStub(Program program, Address addr) {
		return program.getMemory().getBlock(addr).getName().equals(Objc2Constants.OBJC2_STUBS);
	}

	private boolean isObjcAllocCall(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		if (symbol == null) {
			return false;
		}
		String name = symbol.getName();
		return name.startsWith("_objc_alloc");
	}

	private Address getAddressFromVarnode(Program program, Varnode input, int depth,
			TaskMonitor monitor) throws CancelledException {
		if (input == null) {
			return null;
		}
		if (depth >= MAX_RECURSION_DEPTH) {
			return null;
		}
		if (!input.isAddress() && !input.isConstant()) {
			PcodeOp def = input.getDef();
			if (def == null) {
				return null;
			}
			Varnode[] inputs = def.getInputs();
			for (Varnode subInput : inputs) {
				monitor.checkCancelled();
				Address address = getAddressFromVarnode(program, subInput, depth + 1, monitor);
				if (address == null) {
					continue;
				}
				address = getAddressInProgram(program, address.getOffset());
				if (address != null && program.getMemory().contains(address)) {
					return address;
				}
			}
		}
		return input.getAddress();
	}

	private Symbol getSymbolFromVarnode(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return null;
		}
		SymbolTable symbolTable = program.getSymbolTable();
		return symbolTable.getPrimarySymbol(address);
	}

	private String getNameForVarnode(Program program, Function function, Varnode input,
			boolean isClass, boolean isMethod, int depth, int numInputs, TaskMonitor monitor) {
		try {
			if (depth >= MAX_RECURSION_DEPTH) {
				return "<<unknown>>";
			}
			String name = null;
			if (input == null) {
				return null;
			}
			if (input.isAddress() || input.isConstant()) {
				long offset = input.getOffset();
				name = getNameFromOffset(program, offset, input, isClass, isMethod);
			}
			PcodeOp def = input.getDef();
			if (def == null) {
				if (name == null) {
					name = getParamNameOrOffset(function, input, isClass, isMethod, numInputs);
				}
				return name;
			}
			else if (isSuper2Call(program, input) && !isMethod) {
				name = getSuperClassName(program, input, function);
				return name;
			}
			Varnode[] inputs = def.getInputs();
			Address addr = getAddressFromVarnode(program, inputs[0], 0, monitor);
			if (isObjcMsgSendCall(program, inputs[0], addr, monitor)) {
				Symbol objcSymbol = getSymbolFromVarnode(program, inputs[0], monitor);
				int classIndex = 1;
				if (objcSymbol.getName().contains("stret")) {
					classIndex = 2;
				}
				if (inputs.length <= classIndex) {
					PcodeOp callDefinition = inputs[0].getDef();
					if (callDefinition == null) {
						return null;
					}
					inputs = new Varnode[] { callDefinition.getInput(classIndex) };
				}
				else {
					inputs = new Varnode[] { inputs[classIndex] };
				}
				numInputs = 1;
			}
			else if (isClass && isObjcAllocCall(program, inputs[0], monitor)) {
				int classIndex = 1;
				inputs = new Varnode[] { inputs[classIndex] };
			}

			int index = getIndexOfAddress(inputs);
			if (index != -1) {
				name =
					getNameFromOffset(program, inputs[index].getOffset(), input, isClass, isMethod);
				if (name != null) {
					return name;
				}
			}
			for (Varnode subInput : inputs) {
				// If a name was found, just unwind the recursion. If it is just
				// a constant (ex. when determining parameters) keep looking
				// to see if we can find an actual name.
				name = getNameForVarnode(program, function, subInput, isClass, isMethod, depth + 1,
					inputs.length, monitor);
			}
			return name;
		}
		catch (Exception e) {
			return null;
		}
	}

	private int getIndexOfAddress(Varnode[] inputs) {
		for (int i = 0; i < inputs.length; i++) {
			if (inputs[i] == null) {
				continue;
			}
			if (inputs[i].isAddress()) {
				return i;
			}
		}
		return -1;
	}

	private String getSuperClassName(Program program, Varnode input, Function function) {
		String name = null;
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = function.getParentNamespace();
		SymbolIterator symbolIt = symbolTable.getSymbols(namespace.getName());
		while (symbolIt.hasNext()) {
			Symbol symbol = symbolIt.next();
			Address address = symbol.getAddress();
			MemoryBlock block = program.getMemory().getBlock(address);
			if (isObjcDataBlock(block)) {
				Data data = program.getListing().getDataAt(address);
				Data superClassData = data.getComponent(1);
				name = getNameFromData(program, input, true, false, address, superClassData);
			}
		}
		return name;
	}

	private String getParamNameOrOffset(Function function, Varnode input, boolean isClass,
			boolean isMethod, int numInputs) {
		String name = null;
		HighVariable highVar = input.getHigh();
		if (highVar != null) {
			name = highVar.getName();
			if (name != null && name.equals("param_1")) {
				if (numInputs == 1) {
					if (isClass) {
						highVar.getDataType();
						Namespace namespace = function.getParentNamespace();
						if (namespace != null) {
							name = namespace.getName();
						}
					}
				}
				else {
					name = null;
				}
			}
		}
		if (name == null && !isClass && !isMethod) {
			name = "0x" + Long.toString(input.getOffset(), 16);
		}
		return name;
	}

	private String getNameFromOffset(Program program, long offset, Varnode input, boolean isClass,
			boolean isMethod) {
		String name;
		Address address = getAddressInProgram(program, offset);
		if (address == null) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block == null) {
			return null;
		}

		if (isIvarBlock(block) || isObjcConstBlock(block)) {
			name = getIvarName(program, address);
		}
		else if (isMessageRefsBlock(block)) {
			name = getFixupMethodName(program, address);
		}
		else if (isCFStringBlock(block)) {
			name = getCFString(program, address);
			if (name != null) {
				if (name.startsWith("\\")) {
					name = "\\" + name;
				}
				name = "\"" + name + "\"";
			}
		}
		else if (isDataBlock(block)) {
			name = getDataName(program, address);
			if (name != null) {
				if (name.startsWith("\\")) {
					name = "\\" + name;
				}
				name = "\"" + name + "\"";
			}
		}
		else {
			Data nameData = program.getListing().getDataAt(address);
			if (nameData == null) {
				Function function = program.getListing().getFunctionAt(address);
				if (function != null && !function.getName().contains("_objc_msgSend")) {
					DataType returnType = function.getReturnType();
					name = returnType.getName();
					return name;
				}
				return null;
			}
			name = getNameFromData(program, input, isClass, isMethod, address, nameData);
		}
		return name;
	}

	private String getIvarNameFromQualifiedName(String qualifiedName) {
		String iVarName = qualifiedName;
		if (qualifiedName == null) {
			return null;
		}
		if (qualifiedName.contains("::")) {
			String[] classParts = qualifiedName.split("::");
			iVarName = classParts[1];
		}
		return iVarName;
	}

	private String getClassNameFromQualifiedName(String qualifiedName) {
		String className = qualifiedName;
		if (qualifiedName.contains("::")) {
			String[] classParts = qualifiedName.split("::");
			className = classParts[1];
		}
		return className;
	}

	private String getNameFromData(Program program, Varnode input, boolean isClass,
			boolean isMethod, Address address, Data nameData) {
		long offset;
		String name;
		if (!nameData.isDefined()) {
			name = getLabelFromUndefinedData(program, address);
		}
		else {
			Object dataValue = nameData.getValue();
			if (dataValue instanceof String) {
				name = (String) dataValue;
				if (!isClass && !isMethod) {
					name = "\"" + name + "\"";
				}
			}
			else if (dataValue instanceof Address) {
				offset = ((Address) dataValue).getOffset();
				if (offset == address.getOffset()) {
					// Self-referencing pointer
					name = null;
				}
				else {
					name = getNameFromOffset(program, offset, input, isClass, isMethod);
				}
			}
			else {
				name = getClassName2(program, address);
				if (name == null) {
					name = getValueAtAddress(program, address);
				}
			}
		}
		return name;
	}

	private String getDataName(Program program, Address address) {
		// Either a pointer to a string, or a protocol structure
		String name = null;
		Data data = program.getListing().getDataAt(address);
		Address nameAddress = null;
		if (data.isPointer()) {
			Object value = data.getValue();
			nameAddress = (Address) value;
		}
		else {
			Data namePointerData = data.getComponent(1);
			if (namePointerData == null) {
				return null;
			}
			Object namePointerValue = namePointerData.getValue();
			nameAddress = (Address) namePointerValue;
		}
		Data nameData = program.getListing().getDataAt(nameAddress);
		Object nameValue = nameData.getValue();
		if (nameValue instanceof String) {
			name = (String) nameValue;
		}
		else if (isCFStringBlock(program.getMemory().getBlock(nameAddress))) {
			name = getCFString(program, nameAddress);
		}
		return name;
	}

	private String getValueAtAddress(Program program, Address address) {
		String value = null;
		Data data = program.getListing().getDataAt(address);
		Object dataValue = data.getValue();
		if (dataValue instanceof Scalar) {
			value = dataValue.toString();
		}
		return value;
	}

	private String getCFString(Program program, Address address) {
		String name = null;
		Data cfStringData = program.getListing().getDataAt(address);
		Data stringPointer = cfStringData.getComponent(2);
		Object pointerValue = stringPointer.getValue();
		Data stringData = program.getListing().getDataAt((Address) pointerValue);
		Object stringValue = stringData.getValue();
		if (stringValue instanceof String) {
			name = (String) stringValue;
		}
		return name;
	}

	private String getIvarName(Program program, Address address) {
		Listing listing = program.getListing();
		Data ivarOffset = listing.getDataAt(address);
		ReferenceIterator references = ivarOffset.getReferenceIteratorTo();

		while (references.hasNext()) {
			Reference reference = references.next();
			Address fromAddress = reference.getFromAddress();
			MemoryBlock block = program.getMemory().getBlock(fromAddress);
			if (!block.getName().equals(Objc2Constants.OBJC2_CONST)) {
				continue;
			}
			Data ivarList = listing.getDataContaining(fromAddress);
			int numComponents = ivarList.getNumComponents();
			for (int i = 2; i < numComponents; i++) {
				Data ivarData = ivarList.getComponent(i);
				Address ivarAddress = ivarData.getAddress();
				if (ivarAddress.equals(fromAddress)) {
					Data typeDataPointer = ivarData.getComponent(2);
					Object typeAddress = typeDataPointer.getValue();
					String className = null;
					if (typeAddress instanceof Address) {
						Data typeData = listing.getDataAt((Address) typeAddress);
						className = getClassNameFromIvarData(typeData);
					}
					if (className == null) {
						className = "";
					}

					Data nameDataPointer = ivarData.getComponent(1);
					Object nameAddress = nameDataPointer.getValue();
					if (nameAddress instanceof Address) {
						Data nameData = listing.getDataAt((Address) nameAddress);
						String ivarName = (String) nameData.getValue();
						return className + "::" + ivarName;
					}
				}
			}
		}
		return null;
	}

	private String getClassNameFromIvarData(Data typeData) {
		Object typeValue = typeData.getValue();
		String type = null;
		if (typeValue instanceof String) {
			type = (String) typeValue;
			if (type.startsWith("@\"")) {
				type = type.substring(2, type.length() - 1);
			}
			else if (type.startsWith("_")) {
				type = type.substring(1);
			}
		}
		return type;
	}

	private String getFixupMethodName(Program program, Address address) {
		String name = null;
		Data fixupData = program.getListing().getDataAt(address);
		Data messageNamePointer = fixupData.getComponent(1);
		Object messageNameAddress = messageNamePointer.getValue();
		Data messageNameData = program.getListing().getDataAt((Address) messageNameAddress);
		name = (String) messageNameData.getValue();
		return name;
	}

	private Address getAddressInProgram(Program program, long offset) {
		Address address;
		try {
			address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		catch (AddressOutOfBoundsException e) {
			address = null;
		}
		catch (Exception e) {
			address = null;
		}
		return address;
	}

	// Tries to lay down a reference to the function that is actually being called
	private void setReference(Address fromAddress, Program program, String currentClassName,
			String currentMethodName) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol classSymbol = symbolTable.getClassSymbol(currentClassName, (Namespace) null);
		if (classSymbol == null) {
			// TODO: Probably an external class. We could potentially add the method as a new
			// function in the EXTERNAL block, but we'd have to do that in an efficient and
			// thread-safe manner.  Doing so would also require an exclusive checkout, which isn't
			// great. Maybe the loader could reserve chunks for each class symbol it finds, and
			// this could know about the chunks/know where to fill things in.
			return;
		}
		Namespace namespace = (Namespace) classSymbol.getObject();
		List<Symbol> functionSymbols = symbolTable.getSymbols(currentMethodName, namespace);
		if (functionSymbols.isEmpty()) {
			List<Objc2Class> classList = classMap.get(namespace.getName());
			if (classList.size() == 1) {
				Objc2Class superClass = classList.getFirst().getSuperClass();
				setReference(fromAddress, program, superClass.getData().getName(),
					currentMethodName);
				return;
			}
		}

		if (functionSymbols.size() == 1) {
			Address toAddress = functionSymbols.get(0).getAddress();
			ReferenceManager referenceManager = program.getReferenceManager();
			Reference reference = referenceManager.addMemoryReference(fromAddress, toAddress,
				RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, 0);
			referenceManager.setPrimary(reference, true);
		}
	}

	private String getLabelFromUndefinedData(Program program, Address address) {
		Symbol primary = program.getSymbolTable().getPrimarySymbol(address);
		if (primary == null) {
			return null;
		}
		String symbolName = primary.getName();
		if (symbolName.contains("_OBJC_CLASS_$_")) {
			symbolName = symbolName.substring("_OBJC_CLASS_$_".length());
		}
		else if (symbolName.contains(Objc1Constants.OBJC_MSG_SEND)) {
			return null;
		}
		return symbolName;
	}

	private String getClassName2(Program program, Address toAddress) {
		try {
			boolean is32Bit = false;

			int pointerSize = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
			if (pointerSize * 8 == 32) {
				is32Bit = true;
			}
			int nameIndex = is32Bit ? 4 : 3;

			Data classData = program.getListing().getDefinedDataAt(toAddress);

			Data classRwPointerData = classData.getComponent(4);
			Address classRwPointerAddress = (Address) classRwPointerData.getValue();

			Memory memory = program.getMemory();
			MemoryBlock block = memory.getBlock(classRwPointerAddress);

			if (!isObjcConstBlock(block)) {
				return null;
			}

			Data classRwData = program.getListing().getDefinedDataAt(classRwPointerAddress);
			Data classNamePointerData = classRwData.getComponent(nameIndex);

			Address classNameAddress = (Address) classNamePointerData.getValue();
			block = memory.getBlock(classNameAddress);

			if (!isCStringBlock(block) && !isClassNameBlock(block)) {
				return null;
			}

			Data classNameData = program.getListing().getDefinedDataAt(classNameAddress);
			String className = (String) classNameData.getValue();
			return className;
		}
		catch (Exception e) {
			// Too bad. Expecting a class but got something else, don't care.
			// System.out.println();
		}
		return null;
	}

	private List<Function> getFunctionsInTextSection(Program program, AddressSetView set) {
		List<Function> ret = new ArrayList<>();
		Memory mem = program.getMemory();
		for (Function function : program.getFunctionManager().getFunctions(set, true)) {
			Address address = function.getEntryPoint();
			MemoryBlock block = mem.getBlock(address);
			if (block != null && block.getName().equals(SectionNames.TEXT)) {
				ret.add(function);
			}
			
		}
		return ret;
	}

	private boolean isStructReturnCall(Program program, Varnode input, TaskMonitor monitor)
			throws CancelledException {
		Address address = getAddressFromVarnode(program, input, 0, monitor);
		if (address == null) {
			return false;
		}
		Symbol symbol = getSymbolFromVarnode(program, input, monitor);
		return symbol.getName().contains("stret");
	}

	private boolean isSuper2Call(Program program, Varnode input) {
		PcodeOp op = input.getLoneDescend();
		if (op != null && op.getOpcode() == PcodeOp.CALL) {
			Varnode calledAddress = op.getInput(0);
			long offset = calledAddress.getOffset();
			Address address = getAddressInProgram(program, offset);
			if (address == null) {
				return false;
			}
			Function function = program.getListing().getFunctionAt(address);
			if (function.getName().startsWith("_objc_msgSendSuper2")) {
				return true;
			}
		}
		return false;
	}

	private boolean isMessageRefsBlock(MemoryBlock block) {
		return block.getName().equals(Objc2Constants.OBJC2_MESSAGE_REFS);
	}

	private boolean isClassNameBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__objc_classname")) {
				return true;
			}
		}
		return false;
	}

	private boolean isCStringBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals(SectionNames.TEXT_CSTRING)) {
				return true;
			}
		}
		return false;
	}

	private boolean isCFStringBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__cfstring")) {
				return true;
			}
		}
		return false;
	}

	private boolean isDataBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals(SectionNames.DATA)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcDataBlock(MemoryBlock block) {
		if (block != null) {

			if (block.getName().equals(Objc2Constants.OBJC2_DATA)) {
				return true;
			}
		}
		return false;
	}

	private boolean isIvarBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals("__objc_ivar")) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcConstBlock(MemoryBlock block) {
		if (block != null) {
			if (block.getName().equals(Objc2Constants.OBJC2_CONST)) {
				return true;
			}
		}
		return false;
	}

	private void setupDecompiler(Program p, DecompInterface decompiler) {
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(p);
		options.setEliminateUnreachable(false);
		decompiler.setOptions(options);
	}

}
