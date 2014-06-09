#include "disassembler.h"
#include <sstream>
#include <iostream>

#define DEBUG_OUTPUT 0

using namespace std;

Disassembler::Disassembler(PEParser& Parser)
: parser(Parser),
virtualImage{Parser.getVirtualImage()},

codeBounds{parser.getCodeSectionsVirtualBounds()},
imageBase{parser.getImageBase()},
entryPoint{parser.getEntryPoint()},

code{}, branches{}, blocks{}, refdAddrs{}, refs{},
startOfEntrySection{0}, endOfEntrySection{0}
{
    // Find the bounds of the section containing the entry point
	for (pair<uint32_t,uint32_t>& p : codeBounds)
	{
		//cout << "SEC START 0x"<<hex<<p.first-virtualImage<<dec<<endl;
		//cout << "SEC END 0x"<<hex<<p.second-virtualImage<<dec<<endl;
		//cout << "ENTRY 0x"<<hex<<entryPoint-virtualImage<<dec<<endl;
		if (entryPoint>=p.first&&entryPoint<p.second)
		{
			//cout << "SECTION FOUND\n";
			startOfEntrySection=p.first;
			endOfEntrySection=p.second;
			break;
		}
	}
	if (startOfEntrySection==0 || endOfEntrySection==0)
		throw "Invalid entry point or code sections";

	// Time to disasm
	readCode(entryPoint);
}

void Disassembler::readCode(uint32_t addr)
{
	for (uint32_t ip = addr; ip<endOfEntrySection ;)
	{
		if (code.find(ip)!=end(code))
		{
			#if (DEBUG_OUTPUT)
			cout << "Reached already processed instruction, returning\n";
			#endif
			return;
		}

		uint8_t iSize = readInstruction(ip);
		if (iSize==0)
			return;

		vector<uint8_t> newIns = code[ip];
		#if (DEBUG_OUTPUT)
		cout << "New instruction at offset 0x"<<hex<<ip<<" : ";
		for(unsigned i=0; i<newIns.size();++i)
			cout<<(int)newIns[i]<<" ";
		cout<<dec<<"\n";
		#endif

		ip += iSize;

		// Follow branches
		int64_t off=0;
		bool endOfFlow=false; // Set to true if the code flow isn't directly after (e.g. RET or unconditional JMP)
		if (newIns[0]>=0x70 && newIns[0]<=0x7F) // Branch rel8
			off = (int8_t)newIns[1];
		else if (newIns[0]==0xC2 || newIns[0]==0xC3 || newIns[0]==0xCA || newIns[0]==0xCB || newIns[0]==0xCF) // RET
			endOfFlow=true;
		else if (newIns[0]==0xE8) // CALL rel32
			off = (int)(newIns[1] + ((int)newIns[2]<<8) + ((int)newIns[3]<<16) + ((int)newIns[4]<<24));
		else if (newIns[0]==0xE9) // JMP rel32
		{
			off = (int)(newIns[1] + ((int)newIns[2]<<8) + ((int)newIns[3]<<16) + ((int)newIns[4]<<24));
			endOfFlow=true;
		}
		else if (newIns[0]==0xEB)
		{
			off = (int8_t)newIns[1];
			endOfFlow=true;
		}
		else if (newIns[0]==0xFF)
		{
			if (getReg(newIns[1])==2) // CALL Ev
			{
				// We can't follow Ev operands when they refer to the content of a register
				if (getMod(newIns[1])==0 && getRM(newIns[1])==5) // Absolute address
					off = (newIns[2] + ((int)newIns[3]<<8) + ((int)newIns[4]<<16) + ((int)newIns[5]<<24))
					-(int)ip-(int)imageBase; // Make the address absolute, not an offset
				else
				{
					#if (DEBUG_OUTPUT)
					cout << "Couldn't follow call branch refering to a register\n";
					#endif
				}
			}
			else if (getReg(newIns[1])==4) // JMP Ev
			{
				// We can't follow Ev operands when they refer to the content of a register
				if (getMod(newIns[1])==0 && getRM(newIns[1])==5) // Absolute address
				{
					off = (newIns[2] + ((int)newIns[3]<<8) + ((int)newIns[4]<<16) + ((int)newIns[5]<<24))
					-(int)ip-(int)imageBase; // Make the address absolute, not an offset
					endOfFlow=true;
				}
				else
				{
					#if (DEBUG_OUTPUT)
					cout << "Couldn't follow jump branch refering to a register\n";
					#endif
					endOfFlow=true;
				}
			}
			else if (getReg(newIns[1])==3) // CALLF Mp
				throw "CALLF Mp not supported";
			else if (getReg(newIns[1])==5) // JUMPF Mp
				throw "JMPF Mp not supported";
		}
		else if (newIns[0]==0x0F)
		{
			// Two opcodes instructions
			if (newIns[1]>=0x80&&newIns[1]<=0x8F) // JXX Jv
				off = (int)(newIns[2] + ((int)newIns[3]<<8) + ((int)newIns[4]<<16) + ((int)newIns[5]<<24));
		}

		// Find data references
		if (newIns[0]>=0xB8 && newIns[0]<=0xBF) // MOV Zv, Iv
		{
			uint32_t ref = (uint32_t)(newIns[1] + ((int)newIns[2]<<8) + ((int)newIns[3]<<16) + ((int)newIns[4]<<24))-(uint32_t)imageBase;
			if (isAddrInternal(ref))
			{
				// If this addr is known code, don't mark it as may-be-data, if it's already data, then nothing to do.
				if (refdAddrs.find(ref) == end(refdAddrs))
				{
					//cout << "FOUND POSSIBLE DATA REF: 0x"<<hex<<(uint32_t)ref-(int)virtualImage<<dec<<endl;
					refdAddrs.insert(pair<uint32_t,DetectedType>(ref, DetectedType::possibleData));
				}
			}
		}

		if (off!=0)
		{
			// Check bounds
			uint32_t newIp = ip+off;
			//cout <<hex<<"dataSize:0x"<<(int)dataSize<<", newIp:0x"<<(int)(newIp-data)<<dec<<"\n";
			if (!isAddrInternal(newIp))
			{
				#if (DEBUG_OUTPUT)
				cout << "Found branch to external module (0x"<<hex<<(int)(newIp)<<dec<<")\n";;
				#endif
			}
			else
			{
				#if (DEBUG_OUTPUT)
				cout << "Found branch to : 0x"<<hex<<(int)(newIp)<<dec<<"\n";
				#endif
				//cout << "ADDING CODE REF TO : 0x"<<hex<<(int)(newIp-virtualImage)<<dec<<"\n";
				refdAddrs.insert(pair<uint32_t,DetectedType>(newIp, DetectedType::code));
				readCode(newIp);
			}
		}
		if (endOfFlow)
		{
			#if (DEBUG_OUTPUT)
			cout << "Returning after reaching end of flow\n";
			#endif
			return;
		}

		// If we reach a referenced address that isn't a known branch dest, return, since it could be data.
		auto it = refdAddrs.find(ip);
		if (it!=end(refdAddrs))
		{
			if (it->second==DetectedType::possibleData || it->second==DetectedType::data)
			{
				//#if (DEBUG_OUTPUT)
				//cout << "Reached possible data, returning\n";
				//#endif
				return;
			}
			else
			{
				#if (DEBUG_OUTPUT)
				cout << "Reched referenced addr, but it's not data\n";
				#endif
			}
		}
	}
}

uint8_t getMod(uint8_t modrm)
{
	return modrm>>6;
}

uint8_t getReg(uint8_t modrm)
{
	return (modrm>>3)&0b111;
}

uint8_t getRM(uint8_t modrm)
{
	return modrm&0b111;
}

const char* Disassembler::generateOpcodeErrorInfo(const char* error, uint32_t addr)
{
	stringstream es;
	es << error << " (opcode 0x"<<hex<<(uint16_t)*(virtualImage+addr)<<" at offset 0x" <<addr<<")"<<dec;
	es << "\nBTW next opcode is 0x"<<hex<<(uint16_t)*(virtualImage+addr+1)<<dec;
	es << "\nBTW next opcode is 0x"<<hex<<(uint16_t)*(virtualImage+addr+2)<<dec;
	es << "\nBTW next opcode is 0x"<<hex<<(uint16_t)*(virtualImage+addr+3)<<dec;
	string* estr = new string(es.str());
	return estr->c_str();
}

void Disassembler::addOpcodes(std::vector<uint8_t>& instruction, uint32_t addr, unsigned count)
{
	for (unsigned i=0;i<count;++i)
		instruction.push_back(*(virtualImage+addr+i));
}

const std::map<uint32_t ,std::vector<uint8_t>>& Disassembler::getCode()
{
	return code;
}

std::vector<uint8_t> Disassembler::removePrefixes(const std::vector<uint8_t>& instruction)
{
	std::vector<uint8_t> result = instruction;
	while(!instruction.empty())
	{
		uint8_t op = result[0];
		if (op==0xF0 || op==0xF2 || op==0xF3 || op==0x66 || op==0x67 || op==0x2E
			|| op==0x36 || op==0x3E || op==0x26 || op==0x64 || op==0x65)
			result.erase(begin(result));
		else
			break;
	}
	return result;
}

insType Disassembler::getInstructionType(const std::vector<uint8_t>& instruction)
{
	vector<uint8_t> ins = removePrefixes(instruction);

	if (!ins.size())
		return insType::other;
	else if (ins[0]==0x90)
		return insType::nop;
	else if ((ins[0]>=0x70&&ins[0]<=0x7F) || (ins[0]>=0xE0&&ins[0]<=0xE3) || (ins[0]==0x0F&&ins[1]>=0x80&&ins[1]<=0x8F))
		return insType::condJump;
	else if ((ins[0]>=0xE9&&ins[0]<=0xEB) || (ins[0]==0xFF&&(getReg(ins[1])==4||getReg(ins[1])==5)))
		return insType::uncondJump;
	else if (ins[0]==0x9A || ins[0]==0xE8 || (ins[0]==0xFF&&(getReg(ins[1])==2||getReg(ins[1])==3)))
		return insType::call;
	else if (ins[0]==0xC2 || ins[0]==0xC3 || ins[0]==0xCA || ins[0]==0xCB || ins[0]==0xCF)
		return insType::ret;
	else if ((ins[0]>=0xCC&&ins[0]<=0xCE) || ins[0]==0xF1)
		return insType::intCall;
	else if (ins[0]==0x9B || (ins[0]>=0xD8&&ins[0]<=0xDF) || (ins[0]==0x0F&&ins[1]==0x77))
		return insType::x87fpu;
	else if (ins[0]==0x06 || ins[0]==0x07 || ins[0]==0x0E || ins[0]==0x16 || ins[0]==0x17
			|| ins[0]==0x1E || ins[0]==0x1F || (ins[0]>=0x50&&ins[0]<=0x62) || ins[0]==0x68 || ins[0]==0x6A
			|| ins[0]==0x8F || ins[0]==0x9C || ins[0]==0x9D || ins[0]==0xC8 || ins[0]==0xC9
			|| (ins[0]==0xFF&&getReg(ins[1])==6) ||
			(ins[0]==0x0F && (ins[1]==0xA0 || ins[1]==0xA1 || ins[1]==0xA8 || ins[1]==0xA9)))
		return insType::stack;
	else
		return insType::other;
}

opType Disassembler::getOperandsType(const std::vector<uint8_t>& instruction)
{
	vector<uint8_t> ins = removePrefixes(instruction);

	if (!ins.size())
		return opType::none;
	uint8_t op=ins[0];

	if (op==0x6 || op==0x7 || op==0xE || op==0x16 || op==0x17 || op==0x1E || op==0x1F
		|| op==0x27 || op==0x2F || op==0x37 || op==0x3F
		|| (op>=0x40&&op<=0x61) || (op>=0x6C&&op<=0x6F) || (op>=0x90&&op<=0x99)
		|| (op>=0x9B&&op<=0x9F) || (op>=0xA4&&op<=0xA7) || (op>=0xAA&&op<=0xAF) || op==0xC3 || op==0xC9
		|| op==0xCB || op==0xCC || op==0xCE || op==0xCF || op==0xD7 || (op>=0xEC&&op<=0xEF)
		|| op==0xF4 || op==0xF5 || (op>=0xF8&&op<=0xFD) || op==0xF0 || op==0xF2 || op==0xF3
		|| op==0x67 || op==0x66 || op==0x2E || op==0x36 || op==0x3E || op==0x26 || op==0x64 || op==0x65)
		return opType::none;
	else if (op==0x00||op==0x08||op==0x10||op==0x18||op==0x20||op==0x28||op==0x30||op==0x38||op==0x88||op==0x84)
		return opType::EbGb;
	else if (op==0x02||op==0x0A||op==0x12||op==0x1A||op==0x22||op==0x2A||op==0x32||op==0x3A||op==0x8A||op==0x86)
		return opType::GbEb;
	else if (op==0x01||op==0x09||op==0x11||op==0x19||op==0x21||op==0x29||op==0x31||op==0x39||op==0x85||op==0x89)
		return opType::EvGv;
	else if (op==0x03||op==0x0B||op==0x13||op==0x1B||op==0x23||op==0x2B||op==0x33||op==0x3B||op==0x87||op==0x8B)
		return opType::GvEv;
	else if (op==0x8D)
		return opType::GvM;
	else
		return opType::other;
}

bool Disassembler::isPrefix(uint8_t op)
{
	return (op==0xF0 || op==0xF2 || op==0xF3 || op==0x66 || op==0x67 || op==0x2E
			|| op==0x36 || op==0x3E || op==0x26 || op==0x64 || op==0x65);
}

uint32_t Disassembler::getBranchDest(uint32_t addr, std::vector<uint8_t>& instruction)
{
	std::vector<uint8_t> ins = removePrefixes(instruction);
	uint8_t insSize=ins.size();
	if (!insSize)
		throw "Empty instruction";
	else if (instruction[0]==0x66||instruction[0]==0x67)
		throw "Size-override prefixes not supported";
	uint8_t op = ins[0];

	// Relative Jbs
	if ((op>=0x70&&op<=0x7F) || (op>=0xE0&&op<=0xE3) || op==0xEB)
	{
		return addr + insSize + (int8_t)ins[1];
	}
	// Absolute addresses Ap
	else if (op==0xEA || op==0x9A)
	{
		throw "Absolute adresses resolution not implemented (not tested, at least)";
		return addr+(ins[1] + ((int)ins[2]<<8) + ((int)ins[3]<<16) + ((int)ins[4]<<24))-(int)imageBase;
		cout << "RESULT:0x"<<hex<<addr<<dec<<"\n";
	}
	// Relative Jv non-extended
	else if (op==0xE9 || op==0xE8)
	{
		return addr + insSize + (int32_t)((uint32_t)ins[1] + ((uint32_t)(ins[2])<<8)
					+ (((uint32_t)ins[3])<<16) + (((uint32_t)ins[4])<<24));
	}
	// Relative Jv extended
	else if (op==0x0F&&ins[1]>=0x80&&ins[1]<=0x8F)
	{
		return addr + insSize + (int32_t)((uint32_t)ins[2] + ((uint32_t)(ins[3])<<8)
					+ (((uint32_t)ins[4])<<16) + (((uint32_t)ins[5])<<24));
	}
	// Ev
	else if (op==0xFF&&(getReg(ins[1])==2 || getReg(ins[1])==4))
	{
		uint8_t op2=ins[1];
		if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
		{
			return ((uint32_t)ins[2] + ((uint32_t)(ins[3])<<8)
					+ (((uint32_t)ins[4])<<16) + (((uint32_t)ins[5])<<24)) - (uint32_t)imageBase;
		}
		else
			return (uint32_t)-1;
	}
	// Mp
	else if (op==0xFF&&(getReg(ins[1])==3 || getReg(ins[1])==5))
	{
		throw "Mp address resolution not implemented";
	}
	else
		throw "Instruction is not a supported branch instruction";

	// We should never reach this point.
	return 0;
}

void Disassembler::editInstruction(uint32_t addr,std::vector<uint8_t> ins)
{
	code[addr]=ins;
}

bool Disassembler::isAddrInternal(uint32_t addr)
{
	for (pair<uint32_t,uint32_t>& p : codeBounds)
		if (addr>=p.first && addr<p.second)
			return true;
	return false;
}

vector<Branch> Disassembler::getXRefs(uint32_t addr)
{
	vector<Branch> refs;
	for (Branch& b : branches)
	{
		if (b.dest == addr)
			refs.push_back(b);
	}
	return refs;
}

bool Disassembler::hasXRefs(uint32_t addr)
{
	// The keys of refs are the destinations, the values are the sources
	return refs.find(addr) != end(refs);
}

Block* Disassembler::getBlockOfAddr(uint32_t addr)
{
	Block* result=nullptr;

	for (Block& b : blocks)
	{
		if (addr>=b.startAddr && addr<b.endAddr)
		{
			result=&b;
			break;
		}
	}
	return result;
}

bool Disassembler::isAddrInBlock(const uint32_t addr)
{
	// Profiling said we spent ~95% of the time in there during analysis.
	// Reverse iterators turned out to be somewhat faster for the analysis we did
	for (auto s = blocks.rbegin(), e=blocks.rend(); s!=e; ++s)
		if (addr<s->endAddr && addr>=s->startAddr)
			return true;
	return false;
}

void Disassembler::updateVirtualImageFromInstructions()
{
	for (const pair<uint32_t ,std::vector<uint8_t>>& ins : code)
	{
		for (uint8_t i=0; i<ins.second.size(); ++i)
			*(virtualImage+ins.first+i)=ins.second[i];
	}
}
