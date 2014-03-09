#ifndef DECOMPILER_H
#define DECOMPILER_H

#include "objectparser.h"
#include <vector>
#include <map>
#include <stdint.h>
#include <stddef.h>

enum class Register
{
	eax,
	ecx,
	edx,
	ebx,
	esp,
	ebp,
	esi,
	edi,
	none
};

/// Type of an instruction
enum class insType
{
	other,			// Instructions that don't have their own code
	nop,			// Instructions that do nothing, not necessarilly 0x90 (NOP)
	condJump,		// Conditional JMPs
	uncondJump,		// Unconditional JMPs
	call,			// CALL instructions
	ret,			// RET instructions
	intCall,		// Calls to interrupt procedures
	x87fpu,			// x87 instructions for the FPU
	stack			// Stack instructions (POPs/PUSHs)
};

/// Type of the operands of an instruction
enum class opType
{
	other,
	none,
	GvEv,
	EvGv,
	GbEb,
	EbGb,
	GvM,
	Ib,
	Iv
};

enum class BranchType
{
	jump,			// Branches that are always taken
	condJump,		// Branch that can or not be taken
	call,			// Branches both taken then not taken
	regJump,		// Branch depending on a registry (unresolved)
	regCondJump,	// Branch depending on a registry (unresolved)
	regCall			// Branch depending on a registry (unresolved)
};

struct Branch
{
	BranchType type;
	uint8_t* source; 	// Address of the branch instruction
	uint8_t* dest;		// Destination of the branch, or -1 if unresolved
};

/// State of a register at the end of a block of code.
struct BlockRegister
{
	int32_t value=0;				///< Only makes sense if isValueKnown is true
	bool modified=false;			///< True if the value is modified by the function
	bool isValueKnown=false;		///< True if you can guarantee that the register always has this value
	bool inheritedValue=false;		///< True is the value was inherited from a previous block. Implied modified=false.
};

/// Block of code. Jumps can only land at the start of a block, and may only start at the end of a block.
struct Block
{
	uint8_t* startAddr;					///< Address of the first instruction
	uint8_t* endAddr;					///< Just after the last instruction. NOT included in the block
	//BlockRegister registers[8]; 		///< EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
	//bool analyzed=false;				///< True when the register analysis is finished for this block
	std::vector<uint8_t*>& destAddrs;	///< Addresses this block jumps to at the end (not called blocks)

	Block():destAddrs(*(new std::vector<uint8_t*>)){}
};

uint8_t getMod(uint8_t modrm); ///< Gets the MOD part of the ModRM
uint8_t getReg(uint8_t modrm); ///< Gets the Reg part of the ModRM
uint8_t getRM(uint8_t modrm); ///< Gets the R/M part of the ModRM

class Disassembler
{
	public:
		Disassembler(ObjectParser& Parser, bool forceIgnoreErrors=false, bool forceAssumeCodeOnly=false);
		void analyze(); ///< Build the branches and Blocks vectors
		const std::map<uint8_t* ,std::vector<uint8_t>>& getCode();
		void editInstruction(uint8_t* addr,std::vector<uint8_t> ins);
		static insType getInstructionType(const std::vector<uint8_t>& instruction);
		static opType getOperandsType(const std::vector<uint8_t>& instruction);
		/// Returns the instructions without any prefixes
		static std::vector<uint8_t> removePrefixes(const std::vector<uint8_t>& instruction);
		/// Returns the destination of the branch instruction
		/// @param addr Adress of the instruction
		/// @param instruction Must be a branching instruction
		/// @return Destination address, or -1 if the branch depends on a register
		uint8_t* getBranchDest(uint8_t* addr, std::vector<uint8_t>& instruction);
		/// Adds count opcodes to the instruction
		static void addOpcodes(std::vector<uint8_t>& instruction, uint8_t* addr, unsigned count);
		static bool isPrefix(uint8_t op);
		bool isAddrInternal(uint8_t* addr); ///< Is the address inside the data buffer or not
		void updateVirtualImageFromInstructions(); ///< Applies the changes to the intructions to the virtual image
	protected:
		/// Adds the given instruction to the internal code data structure
		/// Throws a const char* if an invalid opcode is encountered
		/// @param addr Address of the instruction to read in the data buffer
		/// @return number of bytes read for this instruction
		uint8_t readInstruction(uint8_t* addr);
		/// Fills the internal code data structure starting from addr in the data buffer
		void readCode(uint8_t* addr);
		/// Append info about the last opcode found
		const char* generateOpcodeErrorInfo(const char* error, uint8_t* addr);
		/// Reads blocks of code (recursively) and add them to blocks
		/// Doesn't analyze the registers of the block.
		Block readBlocks(uint8_t* addr);
		void analyzeBlock(Block& block); ///< Analyzes the registers part of the block
		std::vector<Branch> getXRefs(uint8_t* addr); ///< Finds the branches landing at this address
		bool hasXRefs(uint8_t* addr); ///< Are there branches landing at this address.
		Block* getBlockOfAddr(uint8_t* addr); ///< Gets the block containing this address or nullptr if not found
		bool isAddrInBlock(const uint8_t* const addr);
	private:
		/// Virtual address corresponding to the start of the data block
		uint8_t* virtualImage;
		std::vector<std::pair<uint8_t*,uint8_t*>> codeBounds; ///< Bounds of the executable sections
		std::map<uint8_t* ,std::vector<uint8_t>> code; ///< All the disassembled instructions and their addresses
		uint32_t imageBase;
		std::vector<Branch> branches;
		std::vector<Block> blocks;
		std::multimap<uint8_t*, uint8_t*> refs; ///< The key is the destination, the values are the sources
		uint8_t* entryPoint; ///< Entry point, points inside the virtual image
		uint8_t* startOfEntrySection; ///< Start of the section containing the entry point.
		uint8_t* endOfEntrySection; ///< End of the section containing the entry point.
		ObjectParser& parser;
		bool ignoreErrors;
		/// If true we'll assume we can keep reading after a RET or JMP, and still get valid instructions, not data
		bool assumeCodeOnly;
};

#endif // DECOMPILER_H
