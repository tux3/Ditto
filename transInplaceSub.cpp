#include "transform.h"
#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

unsigned Transform::substitute()
{
	// We need to make a copy, since we'd invalidate the iterators of the original in the middle of the loop.
	const std::map<uint32_t ,std::vector<uint8_t>> code = disasm.getCode();
	unsigned nSubs=0; // Number of instructions substituted, obviously

    for (std::pair<uint32_t ,std::vector<uint8_t>> ins : code)
	{
		if (ins.second.empty())
			continue;
		if (!getRandBool()) // true/false ratio corresponds to the -r XX parameter.
			continue;
		uint8_t op=ins.second[0];
		opType type = disasm.getOperandsType(ins.second);

		// 0x80/0x82 Aliases
		if (op==0x80)
		{
			ins.second[0]=0x82;
			disasm.editInstruction(ins.first, ins.second);
			nSubs++;
			continue;
		}
		else if (op==0x82)
		{
			ins.second[0]=0x80;
			disasm.editInstruction(ins.first, ins.second);
			nSubs++;
			continue;
		}
		// 0xF6/0xF7 /0 /1 TEST aliases
		if (op==0xF6 || op==0xF7)
		{
			uint8_t op2=ins.second[1];
			if (getReg(op2)==0)
			{
				ins.second[1]=op2 | 0b00001000; // Set ModRM:Reg to 1
				disasm.editInstruction(ins.first, ins.second);
				nSubs++;
				continue;
			}
			else if (getReg(op2)==1)
			{
				ins.second[1]=op2 & 0b11110111; // Set ModRM:Reg to 0
				disasm.editInstruction(ins.first, ins.second);
				nSubs++;
				continue;
			}
		}

		// Eb Gb <=> Gb Eb substitutions
		if ((type==opType::EbGb && op!=0x84) || (type==opType::GbEb && op!=0x86))
		{
			uint8_t op2=ins.second[1];
			if (getMod(op2)==3)
			{
				uint8_t reg = getReg(op2), rm=getRM(op2);
				ins.second[0]+= type==opType::EbGb ? 2 : -2; // Invert order
				ins.second[1]=0xC0+(rm<<3)+reg; // Swap registers
				disasm.editInstruction(ins.first, ins.second);
				nSubs++;
				continue;
			}
		}
		// Ev Gv <=> Gv Ev substitutions
		else if ((type==opType::EvGv&&op!=0x85) || (type==opType::GvEv&&op!=0x87))
		{
			uint8_t op2=ins.second[1];
			if (getMod(op2)==3)
			{
				uint8_t reg = getReg(op2), rm=getRM(op2);
				ins.second[0]+= type==opType::EvGv ? 2 : -2; // Invert order
				ins.second[1]=0xC0+(rm<<3)+reg; // Swap registers
				disasm.editInstruction(ins.first, ins.second);
				nSubs++;
				continue;
			}
		}
		// Switch operands of TEST and XCHG instructions
		else if (op>=0x84&&op<=0x87)
		{
			uint8_t op2=ins.second[1];
			if (getMod(op2)==3)
			{
				uint8_t reg = getReg(op2), rm=getRM(op2);
				ins.second[1]=0xC0+(rm<<3)+reg; // Swap registers
				disasm.editInstruction(ins.first, ins.second);
				nSubs++;
				continue;
			}
		}

		// If an instruction uses a SIB byte with a scale of 0 (*1), we can swap base and index
		// Compatible operands : Gv M, Gv Ev, Ev Gv, Gb Eb, Eb Gb and probably others
		if (Disassembler::getOperandsType(ins.second)==opType::GvEv
			|| Disassembler::getOperandsType(ins.second)==opType::EvGv
			|| Disassembler::getOperandsType(ins.second)==opType::GbEb
			|| Disassembler::getOperandsType(ins.second)==opType::EbGb
			|| Disassembler::getOperandsType(ins.second)==opType::GvM)
		{
			uint8_t op2=ins.second[1];
			if (getMod(op2)!=3 && getRM(op2)==4) // No direct register, SIB byte
			{
				uint8_t op3=ins.second[2];
				// If the SIB is correct, we can swap Base and Index
                if (getMod(op3)==0 && getRM(op3)!=4 && getReg(op3)!=4
					&& ((getMod(op2)==0&&getReg(op3)!=5&&getRM(op3)!=5)||getMod(op2)!=0))
				{
					uint8_t reg = getReg(op3), rm=getRM(op3);
					ins.second[2]=(rm<<3)+reg; // Swap registers
					disasm.editInstruction(ins.first, ins.second);
					nSubs++;
					continue;
				}
				// We can modify instructions that use a SIB and an index of ESP (no index) to instead
				// use no SIB and put directly the base register into the ModRM
				// We then have to fill an extra byte with a no-op, we can add
				// a 0x90 NOP before or after, or add a superflous prefix, or
				// if the instruction write to a register we can prepend a 1B instruction that modifies this reg
				// Or we can simply change the Scale to another value
				else if (getReg(op3)==4 && (getMod(op2)!=0 || (getMod(op2)==0&&getRM(op3)!=5)))
				{
					if (getRM(op3)!=4) // Move SIB to ModRM, add NOP
					{
						uint8_t base = getRM(op3);
						ins.second[1]=(op2&0b11111000) | base; // Move the base to the ModRM:RM
						ins.second.erase(begin(ins.second)+2); // Remove the SIB
						pair<uint32_t ,vector<uint8_t>> nopIns;
						nopIns.second.push_back(0x90);
						// Either prepend or append the NOP
						if (::rand()%2) // Prepend
						{
							nopIns.first=ins.first;
							ins.first++;
						}
						else // Append
							nopIns.first=ins.first+ins.second.size();
						disasm.editInstruction(ins.first, ins.second);
						disasm.editInstruction(nopIns.first, nopIns.second);
						nSubs++;
						continue;
					}
					else // Change scale
					{
						uint8_t scale = (getMod(op3) + ::rand()%3+1) & 0b11; // Get a different scale
						ins.second[2]=(op3&0b00111111) | (scale<<6); // Apply new scale
						disasm.editInstruction(ins.first, ins.second);
						nSubs++;
						continue;
					}
				}
			}
			/** TODO
			If an instruction uses a displacement of 0, we can replace it by no-ops
			Replace ADD +X by SUB -X, and the contrary
			Replace XOR REG,REG and equivalents by a random equivalent
			Replace TEST REG,REG by OR REG,REG
			Replace MOV REG1, REG2 by PUSH REG2; POP REG1.
			**/
		}
	}
	return nSubs;
}
