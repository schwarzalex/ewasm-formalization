import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.lang3.EnumUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import secpriv.horst.data.tuples.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EwasmSelectorFunctionProvider {

	private static final Logger LOGGER = LogManager.getLogger(EwasmSelectorFunctionProvider.class);

	private static final int PAGESIZE = 65536;
	Pattern fileIdPattern = Pattern.compile("\\[id(\\d+)\\]"); // matches for example [id3]

	private List<Contract> contractList;
	private List<Integer> noInits = new ArrayList<Integer>() {{
		add(16);
		add(100);
	}};

	public EwasmV13SelectorFunctionProvider() {
		System.out.println("EwasmSelectorFunctionProvider was successfully loaded.");
	}

	public EwasmV13SelectorFunctionProvider(List<String> args) throws IOException {
		contractList = new ArrayList<>();

		for (String arg : args) {
			Contract contract = parseContract(arg);

			String fileName = Paths.get(arg).getFileName().toString();
			Matcher matchId = fileIdPattern.matcher(fileName);
			if (matchId.find()) {
				// parse custom id from filename if available
				contract.id = Integer.parseInt(matchId.group(1));
			} else {
				// generate id from filename if no custom id was provided
				contract.id = Math.abs(fileName.hashCode());
			}
			contractList.add(contract);
			System.out.println(contract);

			if (fileName.contains("[r]")) {
				// reentrancy contract has to be created
				Contract reentrancyContract = new Contract(contract);
				reentrancyContract.id = 100;
				contractList.add(reentrancyContract);
				System.out.println(reentrancyContract);
			}

		}
	}

	public Iterable<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> contractInits() {
		List<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			if (noInits.contains(contract.id)) {
				// do not create the initial state of certain contracts
				// (usually combined with a manual init rule that contains for example abstract values)
				continue;
			}
			result.add(new Tuple5<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(contract.getFirstPositionOfFunction(contract.mainFunctionIndex)), BigInteger.valueOf(100_000_000), BigInteger.valueOf(contract.initialMemorySize), BigInteger.valueOf(contract.getTableSize())));
		}

		return result;
	}

	public Iterable<Tuple3<BigInteger, BigInteger, BigInteger>> contractInit(BigInteger contractId) {
		List<Tuple3<BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		Contract c = getContractForId(contractId.intValue());
		result.add(new Tuple3<>(BigInteger.valueOf(c.getFirstPositionOfFunction(c.mainFunctionIndex)), BigInteger.valueOf(c.initialMemorySize), BigInteger.valueOf(c.getTableSize())));

		return result;
	}

	public Iterable<BigInteger> interval(BigInteger a, BigInteger b) {
		return new Iterable<BigInteger>() {
			@Override
			public Iterator<BigInteger> iterator() {
				return new Iterator<BigInteger>() {
					BigInteger state = a;

					@Override
					public boolean hasNext() {
						return state.compareTo(b) <= 0;
					}

					@Override
					public BigInteger next() {
						BigInteger cur = state;
						state = state.add(BigInteger.ONE);
						return cur;
					}
				};
			}
		};
	}

	public Iterable<Tuple2<BigInteger, BigInteger>> contractAndPcForInstruction(BigInteger instruction) {
		List<Tuple2<BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {
				result.add(new Tuple2<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position)));
			}
		}
		return result;
	}

	public Iterable<Tuple3<BigInteger, BigInteger, BigInteger>> contractAndPcAndValueForInstruction(BigInteger instruction) {
		List<Tuple3<BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {

				// special case for end_function opcode instances where each possible originating call has to be handled
				if (opcodeInstance.opcode == Opcode.END_FUNCTION) {
					for (Integer position : contract.findAllPositionsTargetingFunction(opcodeInstance.immediate.intValue())) {
						result.add(new Tuple3<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), BigInteger.valueOf(position)));
					}
					continue;
				}

				// ELSE opcode has to have the matching END position as value
				if (opcodeInstance.opcode == Opcode.ELSE) {
					OpcodeInstance matchingEnd = contract.getMatchingEndForControlOpcodeInstance(opcodeInstance);
					result.add(new Tuple3<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), BigInteger.valueOf(matchingEnd.position)));
					continue;
				}

				// IF opcode has to either have the first position of the else branch or the position of the END branch if no ELSE exists
				if (opcodeInstance.opcode == Opcode.IF) {
					int position;
					OpcodeInstance matchingElse = contract.getMatchingElseOpcodeInstanceForIf(opcodeInstance);
					if (matchingElse != null) {
						position = matchingElse.position + 1;
					} else {
						// IF does not have an else branch
						position = contract.getMatchingEndForControlOpcodeInstance(opcodeInstance).position;
					}

					result.add(new Tuple3<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), BigInteger.valueOf(position)));
					continue;
				}


				result.add(new Tuple3<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), opcodeInstance.immediate));
			}
		}
		return result;
	}

	public Iterable<Tuple4<BigInteger, BigInteger, BigInteger, BigInteger>> callInformation(BigInteger instruction) {
		List<Tuple4<BigInteger, BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {
				int functionIdx = opcodeInstance.immediate.intValue();
				result.add(new Tuple4<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position),
						BigInteger.valueOf(contract.getNumberOfParametersOfFunction(functionIdx)), BigInteger.valueOf(contract.getFirstPositionOfFunction(functionIdx))));
			}
		}
		return result;
	}

	public Iterable<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, Boolean>> callIndirectInformation(BigInteger instruction) {
		List<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, Boolean>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {
				// each possible table element has to be addressed
				for (Integer functionIdx : contract.table) {

					if (functionIdx == null) {
						// function not initialized, so typeValid is set to false
						result.add(new Tuple5<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), BigInteger.valueOf(-1), BigInteger.valueOf(-1), false));
					}

					int numparam = contract.getNumberOfParametersOfFunction(functionIdx);
					int targetPc = contract.getFirstPositionOfFunction(functionIdx);
					boolean typeValid = opcodeInstance.immediate.intValue() == contract.getCustomTypeOfFunction(functionIdx).index;

					result.add(new Tuple5<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), BigInteger.valueOf(numparam), BigInteger.valueOf(targetPc), typeValid));
				}

			}
		}
		return result;
	}

	public Iterable<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> branchInformation(BigInteger instruction) {
		List<Tuple5<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			// BR
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {
				BigInteger targetPc = BigInteger.valueOf(contract.getTargetPcForBr(opcodeInstance));
				BigInteger heightDifference = BigInteger.valueOf(contract.getStackHeightDifferenceForBranch(opcodeInstance));
				BigInteger numpopped = BigInteger.valueOf(contract.getNumberOfPoppedValuesForBr(opcodeInstance));
				result.add(new Tuple5<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(opcodeInstance.position), targetPc, heightDifference, numpopped));
			}
			if (instruction.intValue() != 12) {
				continue;
			}

			// also RETURN opcodes are handled with the BR rule
			BigInteger returnOpcodeValue = BigInteger.valueOf(15);
			for (OpcodeInstance returnOpcodeInstance : contract.getOpcodeInstancesForOpcodeValue(returnOpcodeValue)) {
				int enclosingFunctionIndex = contract.getFunctionIndexForOpcodeInstance(returnOpcodeInstance);

				OpcodeInstance functionStart = contract.getOpcodeInstanceForPosition(contract.getFirstPositionOfFunction(enclosingFunctionIndex));
				OpcodeInstance functionEnd = contract.getFunctionEndForOpcodeInstance(returnOpcodeInstance);

				// targetPc is equal to the function end
				BigInteger targetPc = BigInteger.valueOf(functionEnd.position);

				// height difference is between the function start and the return opcode instance
				BigInteger stackModificationFromFunctionStart = BigInteger.valueOf(contract.getStackModificationBetweenOpcodeInstances(functionStart, returnOpcodeInstance));

				BigInteger numpopped = BigInteger.valueOf(contract.getCustomTypeOfFunction(enclosingFunctionIndex).getNumberOfReturnValues());
				result.add(new Tuple5<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(returnOpcodeInstance.position), targetPc, stackModificationFromFunctionStart, numpopped));
			}

		}
		return result;
	}

	public Iterable<Tuple6<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> branchTableInformation(BigInteger instruction) {
		List<Tuple6<BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger>> result = new ArrayList<>();

		for (Contract contract : contractList) {
			// BR_TABLE
			for (OpcodeInstance opcodeInstance : contract.getOpcodeInstancesForOpcodeValue(instruction)) {

				// iterate over all target elements
				for (int i = 0; i < opcodeInstance.targets.length; i++) {
					OpcodeInstance tempBrOpcodeInstance = new OpcodeInstance();

					// pretend that for each possible branch value there exists a BR instance
					tempBrOpcodeInstance.opcode = Opcode.BR;
					tempBrOpcodeInstance.position = opcodeInstance.position;
					tempBrOpcodeInstance.immediate = BigInteger.valueOf(opcodeInstance.targets[i]);

					BigInteger targetPc = BigInteger.valueOf(contract.getTargetPcForBr(tempBrOpcodeInstance));

					// the reason for the -1 is that a BR_TABLE always has a const before itself which has to be excluded since it is consumed in this step
					BigInteger heightDifference = BigInteger.valueOf(contract.getStackHeightDifferenceForBranch(tempBrOpcodeInstance) - 1);

					BigInteger numpopped = BigInteger.valueOf(contract.getNumberOfPoppedValuesForBr(tempBrOpcodeInstance));
					result.add(new Tuple6<>(BigInteger.valueOf(contract.id), BigInteger.valueOf(tempBrOpcodeInstance.position), targetPc, heightDifference, numpopped, BigInteger.valueOf(i)));
				}
			}
		}
		return result;
	}

	public Iterable<Tuple2<BigInteger, BigInteger>> globalInits(BigInteger contractId) {
		List<Tuple2<BigInteger, BigInteger>> result = new ArrayList<>();

		Contract c = getContractForId(contractId.intValue());
		for (int i = 0; i < c.globals.size(); i++) {
			result.add(new Tuple2<>(c.globals.get(i), BigInteger.valueOf(i)));
		}

		return result;
	}

	public Iterable<Tuple2<BigInteger, BigInteger>> tableInits(BigInteger contractId) {
		List<Tuple2<BigInteger, BigInteger>> result = new ArrayList<>();

		Contract c = getContractForId(contractId.intValue());

		if (!c.hasTable()) {
			return result;
		}

		for (int i = 0; i < c.table.length; i++) {
			result.add(new Tuple2<>(c.getTableTargetPc(i), BigInteger.valueOf(i)));
		}

		return result;
	}

	public Iterable<Tuple2<BigInteger, BigInteger>> memoryInits(BigInteger contractId) {
		List<Tuple2<BigInteger, BigInteger>> result = new ArrayList<>();

		Contract c = getContractForId(contractId.intValue());
		for (Map.Entry<Integer, Integer> memoryEntry : c.memoryData.entrySet()) {
			result.add(new Tuple2<>(BigInteger.valueOf(memoryEntry.getValue()), BigInteger.valueOf(memoryEntry.getKey())));
		}

		return result;
	}

	public Iterable<BigInteger> pcForContractAndOpcode(BigInteger contractId, BigInteger opcode) {
		List<BigInteger> result = new ArrayList<>();

		Contract c = getContractForId(contractId.intValue());
		for (OpcodeInstance opcodeInstance : c.getOpcodeInstancesForOpcodeValue(opcode)) {
			result.add(BigInteger.valueOf(opcodeInstance.position));
		}

		return result;
	}

	public Iterable<BigInteger> constOps() {
		List<BigInteger> result = new ArrayList<>();

		result.add(BigInteger.valueOf(Opcode.CONSTI32.code));
		result.add(BigInteger.valueOf(Opcode.CONSTI64.code));

		return result;
	}

	public Iterable<BigInteger> cvtOps() {
		List<BigInteger> result = new ArrayList<>();

		result.add(BigInteger.valueOf(Opcode.WRAP_I64.code));

		return result;
	}

	public Iterable<BigInteger> relOps() {
		List<BigInteger> result = new ArrayList<>();

		result.add(BigInteger.valueOf(Opcode.EQI32.code));
		result.add(BigInteger.valueOf(Opcode.NEI32.code));
		result.add(BigInteger.valueOf(Opcode.LT_SI32.code));
		result.add(BigInteger.valueOf(Opcode.LT_UI32.code));
		result.add(BigInteger.valueOf(Opcode.GT_SI32.code));
		result.add(BigInteger.valueOf(Opcode.GT_UI32.code));
		result.add(BigInteger.valueOf(Opcode.LE_SI32.code));
		result.add(BigInteger.valueOf(Opcode.LE_UI32.code));
		result.add(BigInteger.valueOf(Opcode.GE_SI32.code));
		result.add(BigInteger.valueOf(Opcode.GE_UI32.code));
		result.add(BigInteger.valueOf(Opcode.EQI64.code));
		result.add(BigInteger.valueOf(Opcode.NEI64.code));

		return result;
	}

	public Iterable<BigInteger> binOps() {
		List<BigInteger> result = new ArrayList<>();

		result.add(BigInteger.valueOf(Opcode.ADDI32.code));
		result.add(BigInteger.valueOf(Opcode.SUBI32.code));
		result.add(BigInteger.valueOf(Opcode.MULI32.code));
		result.add(BigInteger.valueOf(Opcode.ANDI32.code));
		result.add(BigInteger.valueOf(Opcode.ORI32.code));
		result.add(BigInteger.valueOf(Opcode.XORI32.code));
		result.add(BigInteger.valueOf(Opcode.SHLI32.code));
		result.add(BigInteger.valueOf(Opcode.SHR_UI32.code));
		result.add(BigInteger.valueOf(Opcode.ANDI64.code));
		result.add(BigInteger.valueOf(Opcode.ORI64.code));
		result.add(BigInteger.valueOf(Opcode.XORI64.code));
		result.add(BigInteger.valueOf(Opcode.SHLI64.code));
		result.add(BigInteger.valueOf(Opcode.SHR_UI64.code));

		return result;
	}

	/* EEI get functions */
	public Iterable<BigInteger> eeiGetOnePZeroROps() {
		List<BigInteger> result = new ArrayList<>();

		result.add(BigInteger.valueOf(Opcode.EEI_GETADDRESS.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETCALLER.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETCALLVALUE.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETBLOCKCOINBASE.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETBLOCKDIFFICULTY.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETTXGASPRICE.code));

		return result;
	}

	public Iterable<BigInteger> eeiGetZeroPOneROps() {
		List<BigInteger> result = new ArrayList<>();

		// does not include EEI_GETGASLEFT since there is a separate rule for that
		result.add(BigInteger.valueOf(Opcode.EEI_GETCALLDATASIZE.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETCODESIZE.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETBLOCKGASLIMIT.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETBLOCKNUMBER.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETRETURNDATASIZE.code));
		result.add(BigInteger.valueOf(Opcode.EEI_GETBLOCKTIMESTAMP.code));

		return result;
	}


	public Iterable<BigInteger> eeiCopyOps() {
		List<BigInteger> result = new ArrayList<>();

		// does not include EEI_GETGASLEFT since there is a separate rule for that
		result.add(BigInteger.valueOf(Opcode.EEI_CODECOPY.code));
		result.add(BigInteger.valueOf(Opcode.EEI_RETURNDATACOPY.code));
		result.add(BigInteger.valueOf(Opcode.EEI_CALLDATACOPY.code));

		return result;
	}


	private Contract getContractForId(int contractId) {
		return contractList.stream().filter(c -> c.id == contractId).findFirst().get();
	}

	/*-------------- contract parsing --------------*/

	private static class Contract {

		public int id;
		public List<Integer> functionTypeIndices;
		public int mainFunctionIndex;
		public int initialMemorySize;
		public CustomType[] customTypes;

		public ArrayList<ArrayList<OpcodeInstance>> functions = new ArrayList<>();
		public ArrayList<BigInteger> globals = new ArrayList<>();

		// map of EEI function opcodes and their function index
		public Map<Opcode, Integer> eeiFunctions = new HashMap<>();

		// contains the function ids
		public Integer[] table;

		// data segments as elements for the respective index
		public Map<Integer, Integer> memoryData = new HashMap<>();

		public List<OpcodeInstance> allOpcodeInstances;
		private Map<Opcode, List<OpcodeInstance>> opcodeToOpcodeInstances;

		public Contract() {
		}

		public Contract(Contract otherContract) {
			/*
			the shallow copying below is only fine as long as the objects are immutable
			this is implicitly the case since they are only read in the current setup
			if this changes in the future deep copy mechanisms have to be implemented
			*/
			id = otherContract.id;
			functionTypeIndices = otherContract.functionTypeIndices;
			mainFunctionIndex = otherContract.mainFunctionIndex;
			initialMemorySize = otherContract.initialMemorySize;
			customTypes = otherContract.customTypes;
			functions = otherContract.functions;
			globals = otherContract.globals;
			eeiFunctions = otherContract.eeiFunctions;
			table = otherContract.table;
			memoryData = otherContract.memoryData;
			allOpcodeInstances = otherContract.allOpcodeInstances;
			opcodeToOpcodeInstances = otherContract.opcodeToOpcodeInstances;
		}

		public void generateHelperCollections() {
			if (allOpcodeInstances == null) {
				allOpcodeInstances = new ArrayList<>();
				functions.forEach(opcodeInstances -> allOpcodeInstances.addAll(opcodeInstances));
			}
			if (opcodeToOpcodeInstances == null) {
				opcodeToOpcodeInstances = new HashMap<>();
				for (OpcodeInstance opcodeInstance : allOpcodeInstances) {
					opcodeToOpcodeInstances.computeIfAbsent(opcodeInstance.opcode, k -> new ArrayList<>());
					opcodeToOpcodeInstances.get(opcodeInstance.opcode).add(opcodeInstance);
				}
			}
		}

		public List<OpcodeInstance> getOpcodeInstancesForOpcodeValue(BigInteger opcodeValue) {
			Opcode opcode = Opcode.getOpcode(opcodeValue.intValue());
			return opcodeToOpcodeInstances.getOrDefault(opcode, Collections.emptyList());
		}

		public List<OpcodeInstance> getOpcodeInstancesForOpcode(Opcode opcode) {
			return opcodeToOpcodeInstances.getOrDefault(opcode, Collections.emptyList());
		}

		public OpcodeInstance getOpcodeInstanceForPosition(int position) {
			for (OpcodeInstance opcodeInstance : allOpcodeInstances) {
				if (opcodeInstance.position == position) {
					return opcodeInstance;
				}
			}
			return null;
		}

		public int getTableSize() {
			if (table == null) {
				return 0;
			} else {
				return table.length;
			}
		}

		public boolean hasTable() {
			return table != null;
		}

		/**
		 * Returns a list of all positions from which the specified function is called.
		 * This includes CALL as well as CALL_INDIRECT. Even though for indirect calls it could be checked
		 * more precise (if the function is really in the table), for now all CALL_INDIRECT instructions
		 * are simply added.
		 *
		 * @param functionId the id of the targeted function
		 * @return a list of possible source positions of calls (and all indirect call positions)
		 */
		public List<Integer> findAllPositionsTargetingFunction(int functionId) {
			List<Integer> positionList = new ArrayList<>();
			for (OpcodeInstance opcodeInstance : getOpcodeInstancesForOpcode(Opcode.CALL)) {
				if (BigInteger.valueOf(functionId).compareTo(opcodeInstance.immediate) == 0) {
					positionList.add(opcodeInstance.position);
				}
			}

			for (OpcodeInstance opcodeInstance : getOpcodeInstancesForOpcode(Opcode.CALL_INDIRECT)) {
				positionList.add(opcodeInstance.position);
			}

			return positionList;
		}

		public int getFirstPositionOfFunction(int functionId) {
			return functions.get(functionId).get(0).position;
		}

		public int getLastPositionOfFunction(int functionId) {
			return functions.get(functionId).get(functions.get(functionId).size() - 1).position;
		}

		public CustomType getCustomTypeOfFunction(int functionIndex) {
			return customTypes[functionTypeIndices.get(functionIndex)];
		}

		public int getNumberOfParametersOfFunction(int functionIndex) {
			return getCustomTypeOfFunction(functionIndex).getNumberOfParamters();
		}

		public int getFunctionIndexForOpcodeInstance(OpcodeInstance opcodeInstance) {
			for (int i = 0; i < functions.size(); i++) {
				List<OpcodeInstance> currentFunction = functions.get(i);
				for (OpcodeInstance currentOpcodeInstance : currentFunction) {
					if (currentOpcodeInstance.position == opcodeInstance.position) {
						return i;
					}
				}
			}

			throw new RuntimeException("Opcode instance has to be inside a function.");
		}

		/**
		 * Returns the first position of the function which is saved in the table at the specified index
		 *
		 * @param tableIndex index of table where function index is saved
		 * @return first position of function or -1 if table/table element is null
		 */
		public BigInteger getTableTargetPc(int tableIndex) {
			if (table == null || tableIndex >= table.length || table[tableIndex] == null) {
				return BigInteger.valueOf(-1);
			} else {
				return BigInteger.valueOf(getFirstPositionOfFunction(table[tableIndex]));
			}
		}

		public OpcodeInstance getFunctionEndForOpcodeInstance(OpcodeInstance opcodeInstance) {
			return getOpcodeInstanceForPosition(getLastPositionOfFunction(getFunctionIndexForOpcodeInstance(opcodeInstance)));
		}

		/**
		 * Find the matching END opcode instance for a control opcode instance (BLOCK,LOOP,IF).
		 *
		 * @param controlOpcodeInstance instance of a control opcode
		 * @return the matching END opcode instance
		 */
		public OpcodeInstance getMatchingEndForControlOpcodeInstance(OpcodeInstance controlOpcodeInstance) {
			if (controlOpcodeInstance.opcode != Opcode.BLOCK && controlOpcodeInstance.opcode != Opcode.LOOP && controlOpcodeInstance.opcode != Opcode.IF && controlOpcodeInstance.opcode != Opcode.ELSE) {
				throw new IllegalArgumentException("getMatchingEndForIf can only be called for a control opcode instance (BLOCK,LOOP,IF,ELSE)");
			}

			// Since control structures can be nested the nesting depth has to be tracked.
			// Only if an END on the same level is found it is the correct one.
			int depth = 0;
			for (int i = controlOpcodeInstance.position + 1; i < getLastPositionOfFunction(getFunctionIndexForOpcodeInstance(controlOpcodeInstance)); i++) {
				OpcodeInstance cur = getOpcodeInstanceForPosition(i);

				if (cur.opcode == Opcode.END && depth == 0) {
					return cur;
				}

				if (cur.opcode == Opcode.IF || cur.opcode == Opcode.BLOCK || cur.opcode == Opcode.LOOP) {
					// Depth has to be increased because IF, BLOCK and LOOP all have matching ENDs.
					// ELSE does not increase the depth since it shares the END opcode with an IF.
					depth++;
				}

				if (cur.opcode == Opcode.END) {
					depth--;
				}
			}
			throw new RuntimeException("END opcode instance for control opcode instance has to exist.");
		}

		/**
		 * Find the matching ELSE opcode instance for an IF opcode instance, or return null if ELSE does not exist.
		 *
		 * @param opcodeInstanceIf if opcode instance
		 * @return matching ELSE or null
		 */
		public OpcodeInstance getMatchingElseOpcodeInstanceForIf(OpcodeInstance opcodeInstanceIf) {
			if (opcodeInstanceIf.opcode != Opcode.IF) {
				throw new IllegalArgumentException("getMatchingElseOpcodeInstanceForIf can only be called for an IF instance.");
			}

			int depth = 0;
			for (int i = opcodeInstanceIf.position + 1; i < getMatchingEndForControlOpcodeInstance(opcodeInstanceIf).position; i++) {
				OpcodeInstance cur = getOpcodeInstanceForPosition(i);

				if (cur.opcode == Opcode.ELSE && depth == 0) {
					return cur;
				}

				if (cur.opcode == Opcode.IF || cur.opcode == Opcode.BLOCK || cur.opcode == Opcode.LOOP) {
					// depth has to be increased because nested control structures could also contain ELSE opcode instances
					depth++;
				}

				if (cur.opcode == Opcode.END) {
					depth--;
				}
			}
			return null;
		}

		/**
		 * Find the target opcode instance for the provided BR or BR_IF opcode instance (and not label opcode).
		 * The target in this case is the control opcode instance itself (i.e. LOOP, BLOCK, IF) even though the final target of
		 * BLOCKs and IFs are the end code. The reason for this is that in several cases information about the control opcodes are
		 * needed (e.g. result type).
		 * <p>
		 * In case of a branch to a function null is returned, since there is no dedicated function opcode.
		 *
		 * @param opcodeInstanceBr opcode instance of BR or BR_IF
		 * @return target opcode instance, or null if not found (i.e. function)
		 */
		private OpcodeInstance getTargetOpcodeInstanceForBr(OpcodeInstance opcodeInstanceBr) {
			if (opcodeInstanceBr.opcode != Opcode.BR && opcodeInstanceBr.opcode != Opcode.BR_IF) {
				throw new IllegalArgumentException("getTargetOpcodeInstanceForBr can only be called for a BR or BR_IF instance.");
			}

			int currentDepth = opcodeInstanceBr.immediate.intValue();
			for (int i = opcodeInstanceBr.position - 1; i >= 0; i--) {
				OpcodeInstance cur = getOpcodeInstanceForPosition(i);

				if (currentDepth == 0 && cur.isBlockType()) {
					return cur;
				} else if (cur.opcode == Opcode.END) {
					currentDepth++;
				} else if (cur.isBlockType()) {
					currentDepth--;
				}
			}
			return null;
		}

		/**
		 * Find the target position for the provided BR or BR_IF opcode instance.
		 * - LOOP: the position of the LOOP opcode.
		 * - BLOCK/IF/function: the position of the matching END opcode.
		 *
		 * @param opcodeInstanceBr opcode instance of BR or BR_IF
		 * @return position int
		 */
		public int getTargetPcForBr(OpcodeInstance opcodeInstanceBr) {
			OpcodeInstance targetOpcodeInstance = getTargetOpcodeInstanceForBr(opcodeInstanceBr);

			if (targetOpcodeInstance == null) {
				// branch to a function
				return getFunctionEndForOpcodeInstance(opcodeInstanceBr).position;
			}

			if (targetOpcodeInstance.opcode == Opcode.LOOP) {
				return targetOpcodeInstance.position;
			} else {
				// BLOCK or IF
				OpcodeInstance matchingEnd = getMatchingEndForControlOpcodeInstance(targetOpcodeInstance);
				return matchingEnd.position;
			}
		}

		/**
		 * Find the number of values popped from the value stack which are needed for the branch.
		 *
		 * @param opcodeInstanceBr opcode instance of BR or BR_IF
		 * @return number of values to pop
		 */
		public int getNumberOfPoppedValuesForBr(OpcodeInstance opcodeInstanceBr) {
			if (opcodeInstanceBr.opcode != Opcode.BR && opcodeInstanceBr.opcode != Opcode.BR_IF) {
				throw new IllegalArgumentException("getNumberOfPoppedValuesForBr can only be called for a BR or BR_IF instance.");
			}

			OpcodeInstance targetOpcodeInstance = getTargetOpcodeInstanceForBr(opcodeInstanceBr);

			if (targetOpcodeInstance == null) {
				// branch to function
				return getCustomTypeOfFunction(getFunctionIndexForOpcodeInstance(opcodeInstanceBr)).getNumberOfReturnValues();
			} else if (targetOpcodeInstance.opcode == Opcode.LOOP) {
				// Current WASM specification limits LOOP parameter to 0
				return 0;
			} else if (targetOpcodeInstance.immediateResultType != null) {
				// Current WASM specification limits number of BLOCK or IF results to 0 or 1
				return 1;
			} else {
				return 0;
			}
		}

		/**
		 * Returns the value stack height modification for an opcode instance.
		 * For example an ADDI32 instance would result in the modification -1 (since two values are popped and one is pushed).
		 *
		 * @param opcodeInstance opcode instance
		 * @return stack height modification
		 */
		public int getStackModificationForOpcodeInstance(OpcodeInstance opcodeInstance) {
			Integer modification = Opcode.getStackModificationIfNonDynamic(opcodeInstance.opcode);

			if (modification != null) {
				return modification;
			}

			// dynamic modification value has to be found
			if (opcodeInstance.opcode == Opcode.CALL) {
				return getCustomTypeOfFunction(opcodeInstance.immediate.intValue()).getStackModification();
			} else if (opcodeInstance.opcode == Opcode.CALL_INDIRECT) {
				return customTypes[opcodeInstance.immediate.intValue()].getStackModification();
			}

			throw new RuntimeException("Stack height modification has to exist.");
		}

		/**
		 * Calculate the height of the value stack inside the current function.
		 *
		 * @param opcodeInstance opcode instance
		 * @return stack height
		 * @deprecated use {@link #getStackHeightDifferenceForBranch} instead.
		 */
		@Deprecated
		public int getStackHeightInsideFunction(OpcodeInstance opcodeInstance) {
			int functionIndex = getFunctionIndexForOpcodeInstance(opcodeInstance);

			int currentStackHeight = 0;
			for (int i = getFirstPositionOfFunction(functionIndex); i < opcodeInstance.position; i++) {
				OpcodeInstance currentOpcodeInstance = getOpcodeInstanceForPosition(i);

				// if there is a BLOCK, LOOP or IF it can potentially be skipped and the only change is a possible result type
				if (currentOpcodeInstance.isBlockType() && getMatchingEndForControlOpcodeInstance(currentOpcodeInstance).position <= opcodeInstance.position) {

					if (currentOpcodeInstance.immediateResultType != null) {
						currentStackHeight++;
					}

					i = getMatchingEndForControlOpcodeInstance(currentOpcodeInstance).position;
					continue;
				}

				currentStackHeight += getStackModificationForOpcodeInstance(currentOpcodeInstance);
			}
			return currentStackHeight;
		}

		/**
		 * Calculate the value stack modification between the start and end opcode instance.
		 * Start should have a lower position than end.
		 * The result for a start and end opcode instances which have two i32.const instructions in-between
		 * is +2.
		 *
		 * @param startOpcodeInstance start opcode instance
		 * @param endOpcodeInstance   end opcode instance
		 * @return stack height modification
		 */
		public int getStackModificationBetweenOpcodeInstances(OpcodeInstance startOpcodeInstance, OpcodeInstance endOpcodeInstance) {

			int currentStackHeight = 0;
			for (int i = startOpcodeInstance.position; i < endOpcodeInstance.position; i++) {
				OpcodeInstance currentOpcodeInstance = getOpcodeInstanceForPosition(i);

				// if there is a BLOCK, LOOP or IF it can potentially be skipped and the only change is a possible result type
				if (currentOpcodeInstance.isBlockType() && getMatchingEndForControlOpcodeInstance(currentOpcodeInstance).position <= endOpcodeInstance.position) {

					if (currentOpcodeInstance.immediateResultType != null) {
						currentStackHeight++;
					}

					i = getMatchingEndForControlOpcodeInstance(currentOpcodeInstance).position;
					continue;
				}

				currentStackHeight += getStackModificationForOpcodeInstance(currentOpcodeInstance);
			}
			return currentStackHeight;
		}


		/**
		 * Returns the target stack height for a BR or BR_IF opcode instance.
		 *
		 * @param opcodeInstanceBr the BR or BR_IF opcode instance
		 * @return the stack height of the branch target
		 * @deprecated use {@link #getStackHeightDifferenceForBranch} instead.
		 */
		@Deprecated
		public int getTargetStackHeightForBr(OpcodeInstance opcodeInstanceBr) {
			OpcodeInstance target = getTargetOpcodeInstanceForBr(opcodeInstanceBr);

			if (target == null) {
				// branch to function
				return 0;
			}

			return getStackHeightInsideFunction(target);
		}

		/**
		 * Returns the relative stack height modification between the BR and the target.
		 * For example, a block with a i32.const inside followed by a branch to 0 results in -1.
		 * This negative value is then added in the horst rule to the current ssize.
		 * <p>
		 * The existence of a result value at the target BLOCK does not influence the result
		 * (this is handled directly in the horst rule).
		 *
		 * @param brOpcodeInstance the BR or BR_IF opcode instance
		 * @return the stack height modification
		 */
		public int getStackHeightDifferenceForBranch(OpcodeInstance brOpcodeInstance) {
			OpcodeInstance start = getTargetOpcodeInstanceForBr(brOpcodeInstance);

			if (start == null) {
				// branch to function
				start = getOpcodeInstanceForPosition(getFirstPositionOfFunction(getFunctionIndexForOpcodeInstance(brOpcodeInstance)));
			}

			return getStackModificationBetweenOpcodeInstances(start, brOpcodeInstance);
		}

		@Override
		public String toString() {
			return "Contract{" +
					"id=" + id +
					", functionTypeIndices=" + functionTypeIndices +
					", mainFunctionIndex=" + mainFunctionIndex +
					", initialMemorySize=" + initialMemorySize +
					", customTypes=" + Arrays.toString(customTypes) +
					", functions=" + functions +
					", globals=" + globals +
					", eeiFunctions=" + eeiFunctions +
					", table=" + Arrays.toString(table) +
					", memoryData=" + memoryData +
					",\n\tallOpcodeInstances=" + allOpcodeInstances +
					",\n\topcodeToOpcodeInstances=" + opcodeToOpcodeInstances +
					'}';
		}
	}

	private static class CustomType {
		public int index;
		public List<LanguageType> parameters;
		public LanguageType return_type;

		CustomType(int index, List<LanguageType> parameters, LanguageType return_type) {
			this.index = index;
			this.parameters = parameters;
			this.return_type = return_type;
		}

		public int getNumberOfParamters() {
			return parameters.size();
		}

		public int getNumberOfReturnValues() {
			return return_type == null ? 0 : 1;
		}

		/**
		 * Returns the number of result values (0 or 1) minus the consumed parameters.
		 *
		 * @return the height modification
		 */
		public int getStackModification() {
			int modification = 0;
			if (return_type != null) {
				modification++;
			}
			return modification - getNumberOfParamters();
		}

		@Override
		public String toString() {
			return "CustomType{" +
					"index=" + index +
					", parameters=" + parameters +
					", return_type=" + return_type +
					'}';
		}
	}

	private static class OpcodeInstance {
		public int position;
		public Opcode opcode;
		public BigInteger immediate;

		// only used for br_table targets
		public int[] targets;

		// some opcodes (e.g. IF) have an immediate result type
		public LanguageType immediateResultType;

		public boolean isBlockType() {
			return Opcode.isBlockType(opcode);
		}

		@Override
		public String toString() {
			return "OpcodeInstance{" +
					"position=" + position +
					", opcode=" + opcode +
					", immediate=" + immediate +
					", immediateResultType=" + immediateResultType +
					(targets != null ? (", targets=" + Arrays.toString(targets)) : "") +
					'}';
		}
	}

	public enum LanguageType {
		I32(0x7f),
		I64(0x74),
		ANYFUNC(0x70),
		FUNC(0x60),
		BLOCKTYPE(0x40);

		public final int code;

		LanguageType(int code) {
			this.code = code;
		}

		public static LanguageType getLanguateTypeIgnoreCase(String name) {
			return EnumUtils.getEnumIgnoreCase(LanguageType.class, name);
		}
	}


	public enum Opcode {
		UNREACHABLE(0x00, 0),
		BLOCK(0x02, 0),
		LOOP(0x03, 0),
		IF(0x04, -1),
		ELSE(0x05, 0),
		BR(0x0C, 0),
		BR_IF(0x0D, -1),
		BR_TABLE(0x0E, -1),
		RETURN(0x0F, 0),
		DROP(0x1A, -1),
		SELECT(0x1B, -2),
		GET_GLOBAL(0x17, +1),
		SET_GLOBAL(0x18, -1),
		GET_LOCAL(0x20, +1),
		SET_LOCAL(0x21, -1),
		TEE_LOCAL(0x22, 0),
		CURRENT_MEMORY(0x3F, +1),
		GROW_MEMORY(0x40, 0),
		CONSTI32(0x41, +1),
		CONSTI64(0x42, +1),
		ADDI32(0x6A, -1),
		SUBI32(0x6B, -1),
		MULI32(0x6C, -1),
		EQZI32(0x45, 0),
		EQI32(0x46, -1),
		NEI32(0x47, -1),
		LT_SI32(0x48, -1),
		LT_UI32(0x49, -1),
		GT_SI32(0x4A, -1),
		GT_UI32(0x4B, -1),
		LE_SI32(0x4C, -1),
		LE_UI32(0x4D, -1),
		GE_SI32(0x4E, -1),
		GE_UI32(0x4F, -1),
		EQI64(0x51, -1),
		NEI64(0x52, -1),

		DIV_UI32(0x6E, -1),
		ANDI32(0x71, -1),
		ORI32(0x72, -1),
		XORI32(0x73, -1),
		SHLI32(0x74, -1),
		SHR_UI32(0x76, -1),
		ANDI64(0x83, -1),
		ORI64(0x84, -1),
		XORI64(0x85, -1),
		SHLI64(0x86, -1),
		SHR_UI64(0x88, -1),

		END(0x0B, 0),
		END_FUNCTION(0x10B, 0), // custom opcode in order to differentiate between function end and normal end
		LOADI32(0x28, 0),
		LOADI64(0x29, 0),
		LOAD8_UI32(0x2D, 0),
		STOREI32(0x36, -2),
		STOREI64(0x37, -2),
		STORE8I32(0x3A, -2),
		STORE16I32(0x3B, -2),
		WRAP_I64(0xA7, 0),

		CALL(0x10, 999), // placeholder value since CALL has a dynamic stack modification
		CALL_INDIRECT(0x11, 999),

		// EEI, custom opcodes starting at 0x200
		EEI_GETADDRESS(0x200, -1),
		EEI_GETEXTERNALBALANCE(0x201, -2),
		EEI_GETBLOCKHASH(0x202, -1),
		EEI_GETCALLDATASIZE(0x203, +1),
		EEI_GETCALLER(0x204, -1),
		EEI_GETCALLVALUE(0x205, -1),
		EEI_GETCODESIZE(0x206, +1),
		EEI_GETBLOCKCOINBASE(0x207, -1),
		EEI_GETBLOCKDIFFICULTY(0x208, -1),
		EEI_GETEXTERNALCODESIZE(0x209, 0),
		EEI_GETGASLEFT(0x20A, +1),
		EEI_GETBLOCKGASLIMIT(0x20B, +1),
		EEI_GETTXGASPRICE(0x20C, -1),
		EEI_GETBLOCKNUMBER(0x20D, +1),
		EEI_GETTXORIGIN(0x20E, -1),
		EEI_GETRETURNDATASIZE(0x20F, +1),
		EEI_GETBLOCKTIMESTAMP(0x210, +1),
		EEI_CODECOPY(0x211, -3),
		EEI_EXTERNALCODECOPY(0x212, -4),
		EEI_RETURNDATACOPY(0x213, -3),
		EEI_CALLDATACOPY(0x214, -3),

		EEI_STORAGESTORE(0x215, -2),
		EEI_STORAGELOAD(0x216, -2),

		EEI_CALL(0x217, -4),
		EEI_CALLCODE(0x218, -4),
		EEI_CALLDELEGATE(0x219, -3),
		EEI_CALLSTATIC(0x21A, -3),
		EEI_FINISH(0x21B, -2),
		EEI_REVERT(0x21C, -2),

		EEI_USEGAS(0x21D, -1),
		EEI_LOG(0x21E, -7),
		EEI_SELFDESTRUCT(0x21F, -1),
		EEI_CREATE(0x220, -4);

		public final int code;
		// specifies how the value stack is changed (e.g. const is +1 since a value is pushed onto the stack
		private final int stackModification;

		Opcode(int code, int stackModification) {
			this.code = code;
			this.stackModification = stackModification;
		}

		public static Opcode getOpcode(int code) {
			for (Opcode opcode : Opcode.values()) {
				if (opcode.code == code) {
					return opcode;
				}
			}
			return null;
		}

		public static Opcode getOpcode(String name) {
			return getOpcode(name, null);
		}

		public static Opcode getOpcode(String name, LanguageType type) {
			Opcode foundOpcode = null;

			// some operations contain a "/" in the name which cannot be used as enum name
			String cleanName = name.replace("/", "_");

			foundOpcode = EnumUtils.getEnumIgnoreCase(Opcode.class, cleanName);

			if (foundOpcode == null) {
				foundOpcode = EnumUtils.getEnumIgnoreCase(Opcode.class, cleanName + type);
			}

			if (foundOpcode == null) {
				throw new UnsupportedOperationException("The opcode " + name.toUpperCase() + " (" + type + ") is currently not supported.");
			}

			return foundOpcode;
		}

		/**
		 * Returns the stack modification value or null if opcode updates the stack height dynamically.
		 * For example CALL dynamically reduces the value stack height based on the number or parameters of the target function.
		 *
		 * @param opcode the opcode
		 * @return stack modification value or null
		 */
		public static Integer getStackModificationIfNonDynamic(Opcode opcode) {
			if (opcode.stackModification == 999) {
				return null;
			} else {
				return opcode.stackModification;
			}
		}

		/**
		 * Checks whether the given opcode is of type BLOCK, LOOP or IF
		 *
		 * @param opcode the opcode to check
		 * @return true if block type, false otherwise
		 */
		public static boolean isBlockType(Opcode opcode) {
			List<Opcode> blockTypeOpcodes = Arrays.asList(Opcode.LOOP, Opcode.BLOCK, Opcode.IF);
			return blockTypeOpcodes.contains(opcode);
		}
	}

	/**
	 * Parses the contract at the provided path and returns the new Contract object.
	 * The supported format of a contract is currently limited to the the output of the wasm2json tool
	 * (https://github.com/ewasm/wasm-json-toolkit).
	 *
	 * @param path file path of the json contract
	 * @return contract object
	 * @throws IOException
	 */
	private static Contract parseContract(String path) throws IOException {
		String source = new String(Files.readAllBytes(Paths.get(path)));
		JsonArray jsonContract = new JsonParser().parse(source).getAsJsonArray();

		Contract contract = new Contract();

		// function types
		JsonArray functionTypes = getSection(jsonContract, "function").get("entries").getAsJsonArray();
		contract.functionTypeIndices = new ArrayList<>();
		for (JsonElement functionTypeInt : functionTypes) {
			contract.functionTypeIndices.add(functionTypeInt.getAsInt());
		}

		// custom types
		JsonArray customTypes = getSection(jsonContract, "type").get("entries").getAsJsonArray();
		contract.customTypes = new CustomType[customTypes.size()];
		for (int i = 0; i < customTypes.size(); i++) {
			JsonObject currentType = customTypes.get(i).getAsJsonObject();

			List<LanguageType> parameters = new ArrayList<>();
			for (JsonElement typeJsonElement : currentType.get("params").getAsJsonArray()) {
				String typeString = typeJsonElement.getAsString();
				parameters.add(LanguageType.getLanguateTypeIgnoreCase(typeString));
			}

			LanguageType return_type = null;
			if (currentType.has("return_type")) {
				return_type = LanguageType.getLanguateTypeIgnoreCase(currentType.get("return_type").getAsString());
			}

			contract.customTypes[i] = new CustomType(i, parameters, return_type);
		}

		// main function index
		JsonArray exports = getSection(jsonContract, "export").get("entries").getAsJsonArray();
		for (JsonElement export : exports) {
			if (export.getAsJsonObject().get("kind").getAsString().equals("function")) {
				// only the main function is exported
				contract.mainFunctionIndex = export.getAsJsonObject().get("index").getAsInt();
			}
		}

		// imported EEI function indices
		JsonObject imports = getSection(jsonContract, "import");
		if (imports != null) {
			int currentFunctionIndex = 0; // functions start at index 0 and no other function is parsed at this point

			JsonArray importArray = imports.get("entries").getAsJsonArray();
			for (JsonElement importElem : importArray) {
				if (importElem.getAsJsonObject().get("kind").getAsString().equals("function") && importElem.getAsJsonObject().get("moduleStr").getAsString().equals("ethereum")) {
					String name = importElem.getAsJsonObject().get("fieldStr").getAsString();
					contract.functionTypeIndices.add(currentFunctionIndex, importElem.getAsJsonObject().get("type").getAsInt());
					contract.eeiFunctions.put(Opcode.getOpcode("EEI_" + name), currentFunctionIndex);

					currentFunctionIndex++;
				}
			}
		}

		// in WASM imported functions occupy indices before the functions defined in the contract
		// because of that empty function bodies are added to the function list so that accessing a specific index matches the real fucntion
		for (int i = 0; i < contract.eeiFunctions.size(); i++) {
			contract.functions.add(new ArrayList<>());
		}

		// function bodies
		int pc = 0;
		int functionIndex = 0;
		JsonArray functionBodies = getSection(jsonContract, "code").get("entries").getAsJsonArray();
		for (JsonElement functionBody : functionBodies) {
			ArrayList<OpcodeInstance> opcodeInstances = new ArrayList<>();

			JsonArray jsonInstructions = functionBody.getAsJsonObject().get("code").getAsJsonArray();

			// transform function end opcodes to custom end_function opcodes
			JsonObject end = jsonInstructions.get(jsonInstructions.size() - 1).getAsJsonObject();
			if (end.get("name").getAsString().equals("end")) {
				end.addProperty("name", "end_function");
				end.addProperty("immediates", functionIndex + contract.eeiFunctions.size());
				jsonInstructions.set(jsonInstructions.size() - 1, end);
			}

			for (JsonElement jsonInstruction : jsonInstructions) {
				JsonObject currentInstruction = jsonInstruction.getAsJsonObject();
				OpcodeInstance parsedOpcodeInstance = new OpcodeInstance();

				LanguageType returnType = null;
				if (currentInstruction.has("return_type")) {
					returnType = EnumUtils.getEnumIgnoreCase(LanguageType.class, currentInstruction.get("return_type").getAsString());
				}
				parsedOpcodeInstance.opcode = Opcode.getOpcode(currentInstruction.get("name").getAsString(), returnType);

				if (currentInstruction.has("immediates")) {
					JsonElement immediate = currentInstruction.get("immediates");
					if (immediate.isJsonPrimitive()) {
						if (LanguageType.getLanguateTypeIgnoreCase(immediate.getAsString()) != null) {
							// control structures have the result type in the immediate field
							parsedOpcodeInstance.immediateResultType = LanguageType.getLanguateTypeIgnoreCase(immediate.getAsString());
						} else if (immediate.getAsString().equals("block_type")) {
							// do nothing for now
						} else {
							parsedOpcodeInstance.immediate = immediate.getAsBigInteger();
						}
					} else {
						// store with offset, call_indirect with index, and br_table with targets

						if (immediate.getAsJsonObject().get("offset") != null) {
							parsedOpcodeInstance.immediate = immediate.getAsJsonObject().get("offset").getAsBigInteger();
						} else if (immediate.getAsJsonObject().get("index") != null) {
							parsedOpcodeInstance.immediate = immediate.getAsJsonObject().get("index").getAsBigInteger();
						} else if (immediate.getAsJsonObject().get("targets") != null) {
							JsonArray targetsJsonArray = immediate.getAsJsonObject().get("targets").getAsJsonArray();

							parsedOpcodeInstance.targets = new int[targetsJsonArray.size() + 1];
							for (int i = 0; i < targetsJsonArray.size(); i++) {
								parsedOpcodeInstance.targets[i] = targetsJsonArray.get(i).getAsInt();
							}

							parsedOpcodeInstance.targets[parsedOpcodeInstance.targets.length - 1] = immediate.getAsJsonObject().get("defaultTarget").getAsInt();
						}
					}
				}
				parsedOpcodeInstance.position = pc;

				// if instruction is a call to an EEI function, translate to custom opcode
				if (parsedOpcodeInstance.opcode == Opcode.CALL && contract.eeiFunctions.containsValue(parsedOpcodeInstance.immediate.intValue())) {
					OpcodeInstance eeiOpcodeInstance = new OpcodeInstance();

					// values (function index) of eeiFunctions are unique so the matching key can always be found
					int parsedOpcodeInstanceImmediate = parsedOpcodeInstance.immediate.intValue();
					eeiOpcodeInstance.opcode = contract.eeiFunctions.entrySet().stream().filter(e -> e.getValue().equals(parsedOpcodeInstanceImmediate)).findFirst().get().getKey();

					eeiOpcodeInstance.position = parsedOpcodeInstance.position;
					parsedOpcodeInstance = eeiOpcodeInstance;
				}

				opcodeInstances.add(parsedOpcodeInstance);
				pc++;
			}
			contract.functions.add(opcodeInstances);
			functionIndex++;
		}

		// fill result types off CALL instances since they do not contain the result type as immediate in the json file
		// this step could potentially be moved to a different stage in the contract parsing procedure
		for (List<OpcodeInstance> function : contract.functions) {
			for (OpcodeInstance opcodeInstance : function) {
				if (opcodeInstance.opcode == Opcode.CALL) {
					LanguageType return_type = contract.getCustomTypeOfFunction(opcodeInstance.immediate.intValue()).return_type;
					if (return_type != null) {
						opcodeInstance.immediateResultType = return_type;
					}
				}
			}
		}

		// initial memory size
		JsonObject memorySection = getSection(jsonContract, "memory");
		contract.initialMemorySize = memorySection.get("entries").getAsJsonArray().get(0).getAsJsonObject().get("intial").getAsInt() * PAGESIZE;

		// globals
		JsonObject globalSection = getSection(jsonContract, "global");
		if (globalSection != null) {
			JsonArray globals = globalSection.get("entries").getAsJsonArray();

			for (JsonElement global : globals) {
				contract.globals.add(global.getAsJsonObject().get("init").getAsJsonObject().get("immediates").getAsBigInteger());
			}
		}

		// table
		JsonObject tableSection = getSection(jsonContract, "table");
		if (tableSection != null) {
			// only one table is currently allowed in WASM
			JsonObject table = tableSection.get("entries").getAsJsonArray().get(0).getAsJsonObject();
			int size = table.get("limits").getAsJsonObject().get("intial").getAsInt();

			contract.table = new Integer[size];
		}

		// table elements
		JsonObject elementSection = getSection(jsonContract, "element");
		if (elementSection != null) {
			JsonArray elementsEntries = elementSection.get("entries").getAsJsonArray();

			for (JsonElement elementEntry : elementsEntries) {
				int offset = elementEntry.getAsJsonObject().get("offset").getAsJsonObject().get("immediates").getAsInt();
				JsonArray elements = elementEntry.getAsJsonObject().get("elements").getAsJsonArray();

				for (int tableOffset = offset, elementOffset = 0; elementOffset < elements.size(); tableOffset++, elementOffset++) {
					contract.table[tableOffset] = elements.get(elementOffset).getAsInt();
				}
			}
		}

		// memory data
		JsonObject dataSection = getSection(jsonContract, "data");
		if (dataSection != null) {
			JsonArray segments = dataSection.get("entries").getAsJsonArray();

			for (JsonElement segment : segments) {
				int offset = segment.getAsJsonObject().get("offset").getAsJsonObject().get("immediates").getAsInt();

				JsonArray dataElements = segment.getAsJsonObject().get("data").getAsJsonArray();
				for (JsonElement dataElement : dataElements) {
					int value = dataElement.getAsInt();
					contract.memoryData.put(offset, value);
					offset++;
				}

			}
		}

		contract.generateHelperCollections();
		return contract;
	}

	private static JsonObject getSection(JsonArray jsonContract, String sectionName) {
		JsonObject section = null;

		for (JsonElement element : jsonContract) {
			JsonObject currentSection = element.getAsJsonObject();
			if (currentSection.get("name").getAsString().equals(sectionName)) {
				section = currentSection;
				break;
			}
		}

		return section;
	}
}