#include "disassembler.h"
#include <sstream>
#include <iostream>

using namespace std;

void Disassembler::analyze()
{
	/// IDA just draws the end of a block just after each jump, or just before the landing point of a jump
	/// If a src block jumps in the middle of a dst block, the dst block is to be cut into two blocks
	/// Eack block can be linked to any number of block, and receive links from any number of blocks, including itself
	/// A function is a vector of blocks jumping and jumped to only with blocks of the same function.

	/**
	We need functions to determine what instructions are reading/writing and from/to what (reg, mem, pins, ints, ...)
	We should be able to analyze what registers are in use at what time. A register is not in use if we're after the
	last read to it and before the first write to it.
	We should be able to determine the parameters of a function, if a function reads a value before writing it, it's
	likely a parameter.
	We should be able to detect jump tables, and we should be able to detect the possible destinations of a jump or
	call using a register.

	The disassembler should have fast functions to update the code data structure
	Those functions must updates the keys (addresses) of the code structure, and the explicitely modified values.
	Those functions must not attempt to correct the values of other instructions (relocations)
	A funstion to overwrite an instruction or range of instructions
	A function to insert an instruction or range of instructions
	A function to move an instruction or range of instructions
	The disassembler should have a function to relocate all the values around an address by a given offset around
	E.g if the address is 0xAAAA and the offset is 5, all the references from addresses <0xAAAA to addresses >=0xAAAA
	will be offseted by +5 and all the references from addresses >=0xAAAA to addresses <0xAAAA will be offsetted by -5
	This corresponds to the relocation for inserting 5 bytes at address 0xAAAA
	**/

	/// IDA can resolve some register-dependant jumps.
	/// Often we have X blocks higher : mov reg, ds:0xXXXXXX, then later call reg
	/// We should store what registers are modified by what blocks, and to what values if we know.
	/// But most of the time, those register-dependant jumps are used to call imports, not internal addresses.

	// Build initial branches vector and refs map
	branches.clear();
	for (std::pair<uint32_t ,std::vector<uint8_t>> elem : code)
	{
		insType iType = getInstructionType(elem.second);
		if (iType==insType::condJump)
		{
			uint32_t dest = getBranchDest(elem.first, elem.second);
			if (dest==(uint32_t)-1)
				branches.push_back({BranchType::regCondJump, elem.first, dest});
			else
			{
				branches.push_back({BranchType::condJump, elem.first, dest});
				refs.insert({dest,elem.first}); // The key is the destination, values are sources
			}
		}
		else if (iType==insType::uncondJump)
		{
			uint32_t dest = getBranchDest(elem.first, elem.second);
			if (dest==(uint32_t)-1)
				branches.push_back({BranchType::regJump, elem.first, dest});
			else
			{
				branches.push_back({BranchType::jump, elem.first, dest});
				refs.insert({dest,elem.first}); // The key is the destination, values are sources
			}
		}
		else if (iType==insType::call)
		{
			uint32_t dest = getBranchDest(elem.first, elem.second);
			if (dest==(uint32_t)-1)
				branches.push_back({BranchType::regCall, elem.first, dest});
			else
			{
				branches.push_back({BranchType::call, elem.first, dest});
				refs.insert({dest,elem.first}); // The key is the destination, values are sources
			}
		}
	}

	// Build initial blocks vector (jump flow analysis)
	blocks.clear();
	readBlocks(entryPoint);
	for (Branch& b : branches)
		if (b.type==BranchType::call && isAddrInternal(b.dest))
			readBlocks(b.dest);

	/// TODO: Analyze blocks to find what registers are modified and with what
	/// Use register analysis at the same time to resolve some register dependant calls
	/// If we can resolve a register-dependant branch, add it to a temp vector of resolved branches and
	/// finish analysing the current block.
	/// Then disassemble the code pointed by the newly resolved jumps (using readCode())

	/// Read blocks of the code pointed by the newly resolved jumps
	/// If the new jumps lands in the middle of another block, readBlock() will split the block in half.
	/// If we need to split a block in half, we have to cancel the previous analysis done on the block.

	/** BLOCK ANALYSIS
	If the block was already analyzed, return;
	Work on a temporary BlockRegister[8] array, not directly on the block's array.
	Read the instructions, if a register is given a value from read-only memory, fetch that value
	If a register is modified, keep up with the modifications
	If it is impossible to guarantee that the register will always have this value, mark it as unknown
	If a CALL is encountered, do not follow it, and assume that EAX, ECX and EDX have been modified and are unknown.
	If an instruction is unknown (can't determine the modification), assume that all registers are modified and unknown.
	Use a function BlockRegister[8] emulate(BlockRegister[8], vector<uint8_t>) that emulates the effect of one
	instruction on the registers and give the result. If an instruction tries to read from another section that isn't
	a read-only section, consider that the value read is unknown.
	When reaching the end of the block :
	If we have inherited registers, but we know that they are modified, override the inheritance with what we know.
	if the next block isn't analyzed yet, don't analyze it. Set the analyzed flag for our block.
	If we know the value of a register and if the next block knowns the value of the register by inheritance
	and the value is different, mark the value as unknown by inheritance, if the value is the same, do nothing.
	If in the next block the value is unknown, unmodified, and not inherited yet, set the value with ours.
	**/
}

Block Disassembler::readBlocks(uint32_t addr)
{
	//cout << "Reading 0x"<<hex<<(int)addr-(int)data<<dec<<" ";
	vector<uint8_t> firstIns=code[addr];
	uint8_t insSize = firstIns.size();
	insType iType = getInstructionType(firstIns);

	if (insSize==0)
		throw "Instruction with null size while reading blocks (start)";

	// Start with a block of 1 instruction
	Block block;
	block.startAddr=addr;
	block.endAddr=addr+insSize;

	// If the first instruction is a jump or ret, stop here
	if (iType==insType::condJump)
	{
		blocks.push_back(block);
		uint32_t jumpDest = getBranchDest(addr, firstIns);
		if (jumpDest!=(uint32_t)-1 && isAddrInternal(jumpDest))
			if (!isAddrInBlock(jumpDest))
			{
				//cout << "Jumping cond to taken 0x"<<hex<<(int)jumpDest-(int)data<<dec<<"\n";
				readBlocks(jumpDest);
			}
		if (!isAddrInBlock(addr+insSize))
		{
			//cout << "Jumping cond to alter 0x"<<hex<<(int)addr+insSize-(int)data<<dec<<"\n";
			readBlocks(addr+insSize);
		}
		return block;
	}
	else if(iType==insType::uncondJump)
	{
		blocks.push_back(block);
		uint32_t jumpDest = getBranchDest(addr, firstIns);
		if (jumpDest!=(uint32_t)-1 && isAddrInternal(jumpDest))
			if (!isAddrInBlock(jumpDest))
			{
				//cout << "Jumping cond to taken 0x"<<hex<<(int)jumpDest-(int)data<<dec<<"\n";
				readBlocks(jumpDest);
			}
		return block;
	}
	else if(iType==insType::ret)
	{
		blocks.push_back(block);
		return block;
	}

	// Process the rest of the block
	addr+=insSize;
	for (;;)
	{
		//cout << "Checking 0x"<<hex<<(int)addr-(int)data<<dec<<" ";
		vector<uint8_t> ins = code[addr];
		insSize = ins.size();
		iType = getInstructionType(ins);

		if (insSize==0)
			throw "Instruction with null size while reading blocks";

		// If instruction is a jump or ret, add it and stop (and process jumps recursively)
		if (iType==insType::condJump)
		{
			block.endAddr+=insSize;
			blocks.push_back(block);
			uint32_t jumpDest = getBranchDest(addr, ins);
			if (jumpDest!=(uint32_t)-1 && isAddrInternal(jumpDest))
				if (!isAddrInBlock(jumpDest))
				{
					//cout << "Jumping cond to taken 0x"<<hex<<(int)jumpDest-(int)data<<dec<<"\n";
					readBlocks(jumpDest);
				}
			if (!isAddrInBlock(addr+insSize))
			{
				//cout << "Jumping cond to alter 0x"<<hex<<(int)addr+insSize-(int)data<<dec<<"\n";
				readBlocks(addr+insSize);
			}
			return block;
		}
		else if(iType==insType::uncondJump)
		{
			block.endAddr+=insSize;
			blocks.push_back(block);
			uint32_t jumpDest = getBranchDest(addr, ins);
			if (jumpDest!=(uint32_t)-1 && isAddrInternal(jumpDest))
				if (!isAddrInBlock(jumpDest))
				{
					//cout << "Jumping uncond to taken 0x"<<hex<<(int)jumpDest-(int)data<<dec<<"\n";
					readBlocks(jumpDest);
				}
			return block;
		}
		else if(iType==insType::ret)
		{
			block.endAddr+=insSize;
			blocks.push_back(block);
			return block;
		}

		// If the instruction is xref'd, stop here without adding it.
		if (hasXRefs(addr))
		{
			block.destAddrs.push_back(addr);
			blocks.push_back(block);

			if (!isAddrInBlock(addr))
				readBlocks(addr);

			return block;
		}

		// Regular instruction, add it to the block
		block.endAddr+=insSize;
		addr+=insSize;
	}
	return block;
}
