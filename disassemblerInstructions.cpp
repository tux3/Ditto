#include "disassembler.h"

using namespace std;

uint8_t Disassembler::readInstruction(uint32_t addr)
{
	vector<uint8_t> instruction;
	uint8_t instructionSize = 0;
	uint8_t op = *(virtualImage+addr);
	bool pf1=false; // Prefix of group 1 present
	bool pf2=false; // Prefix of group 2 present
	bool opSize=false; // Operand-size override
	bool adSize=false; // Address-size override

	// Disable the address-size override prefix until we implement it
	if (op==0x67)
		throw generateOpcodeErrorInfo("Address-size override prefix not implemented",addr);

	// Mark prefixes
	bool keepSearchingPrefixes=true;
	while (keepSearchingPrefixes)
	{
		keepSearchingPrefixes=false;
		if (op==0xF0 || op==0xF2 || op==0xF3)
		{
			keepSearchingPrefixes=true;
			pf1=true;
			addr++;
			op=*(virtualImage+addr);
		}
		if (op==0x67)
		{
			keepSearchingPrefixes=true;
			adSize=true;
			addr++;
			op=*(virtualImage+addr);
		}
		if (op==0x66)
		{
			keepSearchingPrefixes=true;
			opSize=true;
			addr++;
			op=*(virtualImage+addr);
		}
		if (op==0x2E || op==0x36 || op==0x3E || op==0x26 || op==0x64 || op==0x65)
		{
			keepSearchingPrefixes=true;
			pf2=true;
			addr++;
			op=*(virtualImage+addr);
		}
	}

	// Handle one-byte instructions
    if (op==0x6 || op==0x7 || op==0xE || op==0x16 || op==0x17 || op==0x1E || op==0x1F
		|| op==0x27 || op==0x2F || op==0x37 || op==0x3F
		|| (op>=0x40&&op<=0x61) || (op>=0x6C&&op<=0x6F) || (op>=0x90&&op<=0x99)
		|| (op>=0x9B&&op<=0x9F) || (op>=0xA4&&op<=0xA7) || (op>=0xAA&&op<=0xAF) || op==0xC3 || op==0xC9
		|| op==0xCB || op==0xCC || op==0xCE || op==0xCF || op==0xD7 || (op>=0xEC&&op<=0xEF)
		|| op==0xF4 || op==0xF5 || (op>=0xF8&&op<=0xFD))
	{
		instructionSize=1;
	}

	// Two or more bytes instructions from now on
	uint8_t op2 = *(virtualImage+addr+1);

	// One opcode instructions (but >1 bytes)
	if (op==0x05 || op==0x0D || op==0x25 || op==0x2D || op==0x35 || op==0x3D || op==0x68 || op==0xA9
		|| (op>=0xB8&&op<=0xBF) || op==0xE9 || op==0xE8) // XXX Iv and XXX Jv
	{
		if (opSize)		instructionSize=3;
		else			instructionSize=5;
	}
	else if ((op>=0x70 && op<=0x7F) || op==0x04 || op==0x0C || op==0x14 || op==0x1C || op==0x24 || op==0x2C || op==0x34
			|| op==0x3C || op==0x6A || op==0xCD || op==0xEB || op==0xA8 || (op>=0xB0&&op<=0xB7)) // JXX rel8 and XXX Ib
		instructionSize=2;
	else if (op==0xA0 || op==0xA2) // XXX Ob
		instructionSize=5;
	else if (op==0x80 || op==0x82 || op==0xC0 || op==0xC6) // XXX Eb Ib
	{
		if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (op3==5) // Full displacement
				instructionSize=8;
			else // No displacement
				instructionSize=4;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute address
			instructionSize=7;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3 = *(virtualImage+addr+2);
            if (getRM(op3)!=5) // No displacement
				instructionSize=4;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=4;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=5;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=7;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=8;
		else if (getMod(op2)==3) // Direct register
			instructionSize=3;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x69) // Gv Ev Iv
	{
		if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=7;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=8;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=10;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=11;
		else if (getMod(op2)==3) // Direct register
			instructionSize=6;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x6B) // Gv Ev Ibs
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=3;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x81) // XXX Ev Iv
	{
		if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=7;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute addess, no displacement
			instructionSize=10;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=7;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=8;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=10;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=11;
		else if (getMod(op2)==3) // Direct register
			instructionSize=6;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			instructionSize-=2;
	}
	else if (op==0x83 || op==0xC1) // XXX Ev Ibs or Ev Ib
	{
		if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=4;
			else // Full displacement
				instructionSize=8;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute memory address
			instructionSize=7;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=4;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=5;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=7;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=8;
		else if (getMod(op2)==3) // Register used directly as operand
			instructionSize=3;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x00 || op==0x02 || op==0x08 || op==0x0A || op==0x10 || op==0x18 || op==0x1A || op==0x20 || op==0x22
			|| op==0x28 || op==0x2A || op==0x30 || op==0x32 || op==0x38 || op==0x3A || op==0x84 || op==0xD2
			|| op==0x86 || op==0x88 || op==0x8A || op==0x8C) // XXX Eb Gb or XXX Gb Eb
	{
		if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)==5) // Full displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute memory address
			instructionSize=6;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x01 || op==0x09 || op==0x11 || op==0x19 || op==0x21 || op==0x29 || op==0x31
			|| op==0x39 || op==0x85 || op==0x89) // XXX Ev Gv
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, indirect register
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB byte
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=3;
			else // Full displacement
				instructionSize=7;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute address
			instructionSize=6;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB byte
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB byte
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB byte
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB byte
			instructionSize=7;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x03 || op==0x0B || op==0x13 || op==0x1B || op==0x23
			|| op==0x2B || op==0x33 || op==0x3B || op==0x87 || op==0x8B) // XXX Gv Ev
	{
		if (getMod(op2)==0 && getRM(op2)==5) // no displacement, absolute address
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // no displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)==5) // Full displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, indirect reg
			instructionSize=2;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0x8D) // LEA Gv M
	{
		if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3 = *(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=3;
			else // Full displacement
                instructionSize=7;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0xA1 || op==0xA3) // MOV EAX 0v or MOV 0v EAX
		instructionSize=5;
	else if (op==0xC2 || op==0xCA) // RET Iw
		instructionSize=3;
	else if (op==0xC7 && getReg(op2)==0) // MOV Ev Iv
	{
		if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB byte
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, using SIB byte
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=7;
			else // Full displacement
				instructionSize=11;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute address
			instructionSize=10;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1 byte displacement, no SIB byte
			instructionSize=7;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1 byte displacement, SIB byte
			instructionSize=8;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB byte
			instructionSize=10;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB byte
			instructionSize=11;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			instructionSize-=2;
	}
	else if (op==0x8F || op==0xD1 || op==0xD3) // XXX Ev
	{
		if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // no displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==5) // no displacement, absolute address
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // no displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)==5) // Full displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==1 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0xD8) // D8 group (x87fpu instructions)
	{
		if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==4) // // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)==5) // Full displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
			instructionSize=6;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xD9) // D9 group (x87fpu instructions)
	{
		if ((op2>=0xE0 && op2<=0xE5) || (op2>=0xE8 && op2<=0xEE) || op2==0xC9 || op2==0xD0)
			instructionSize=2;
		else if (getReg(op2)==0 || getReg(op2)==2 || getReg(op2)==6) // /0, /2 or /6
		{
			if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
				instructionSize=2;
			else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)!=5) // No displacement
					instructionSize=3;
				else // Full displacement
					instructionSize=7;
			}
			else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
				instructionSize=6;
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=4;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=6;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=7;
			else if (getMod(op2)==3) // /0 direct register
				instructionSize=2;
		}
		else if ((getReg(op2)==3||getReg(op2)==5)
				&& getMod(op2)==0 && getRM(op2)==5) // /3,/5, Absolute address
				instructionSize=6;
		else if ((getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==0 && getRM(op2)==4) // /3,/5 or /7, No displacement, SIB
		{
            uint8_t op3=*(virtualImage+addr+2);
            if (getRM(op3)!=5) // No displacement
				instructionSize=3;
		}
		else if ((getReg(op2)==2||getReg(op2)==3) && getMod(op2)==0
				&& getRM(op2)!=4 && getRM(op2)!=5) // /2 or /3, No displacement, no SIB
			instructionSize=2;
		else if ((getReg(op2)==2||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==1 && getRM(op2)!=4) // /2,/3,/5 or /7, 1B displacement, no SIB
			instructionSize=3;
		else if ((getReg(op2)==2||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
					&& getMod(op2)==1 && getRM(op2)==4) // /2,/3,/5 or /7, 1B displacement, SIB
			instructionSize=4;
		else if ((getReg(op2)==2||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==2 && getRM(op2)!=4) // /2,/3,/5 or /7, Full displacement, no SIB
			instructionSize=6;
		else if ((getReg(op2)==2||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==2 && getRM(op2)==4) // /2,/3,/5 or /7, Full displacement, SIB
			instructionSize=7;
		else if ((getReg(op2)==1||getReg(op2)==2||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==3) // /1,/2,/3,/5 or /7, Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xDA) // DA group (x87fpu instructions)
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
	}
	else if (op==0xDB) // DB group (x87fpu instructions)
	{
		if (op2>=0xE0&&op2<=0xE4)
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5) // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xDC) // DC group (x87fpu instructions)
	{
		if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)==5) // Full displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
			instructionSize=6;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xDD) // DD group (x87fpu instructions)
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else if (getReg(op2)==0 || getReg(op2)==3 || getReg(op2)==4
				|| getReg(op2)==6 || getReg(op2)==7) // /0,/3,/4,/6 or /7
		{
			if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // no displacement, no SIB
				instructionSize=2;
			else if (getMod(op2)==0 && getRM(op2)==5) // no displacement, absolute address
				instructionSize=6;
			else if (getMod(op2)==0 && getRM(op2)==4) // no displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)==5) // Full displacement
					instructionSize=7;
				else // No displacement
					instructionSize=3;
			}
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=4;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=6;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=7;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else if (getReg(op2)==2) // /2
		{
			if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2) != 5) // no displacement, no SIB
				instructionSize=2;
			else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
				instructionSize=6;
			else if (getMod(op2)==0 && getRM(op2)==4) // no displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)!=5) // No displacement
					instructionSize=3;
			}
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=4;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=6;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=7;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xDE) // DE group (x87fpu instructions)
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xDF) // DF group (x87fpu instructions)
	{
		if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else if((getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // /5 or /7, no displacement, no SIB
			instructionSize=2;
		else if ((getReg(op2)==5) && getMod(op2)==0 && getRM(op2)==5) // /5, absolute address
			instructionSize=6;
		else if((getReg(op2)==0||getReg(op2)==3||getReg(op2)==5||getReg(op2)==7)
				&& getMod(op2)==0 && getRM(op2)==4) // /0,/3,/5 or /7, no displacement, SIB
		{
			uint8_t op3=*(virtualImage+addr+2);
			if (getRM(op3)!=5)
				instructionSize=3; // No displacement
		}
		else if((getReg(op2)==5 || getReg(op2)==7) && getMod(op2)==1 && getRM(op2)!=4) // /5 or /7, 1B displacement, no SIB
			instructionSize=3;
		else if((getReg(op2)==5 || getReg(op2)==7) && getMod(op2)==1 && getRM(op2)==4) // /5 or /7, 1B displacement, SIB
			instructionSize=4;
		else if((getReg(op2)==5 || getReg(op2)==7) && getMod(op2)==2 && getRM(op2)!=4) // /5 or /7, Full displacement, no SIB
			instructionSize=6;
		else if((getReg(op2)==5 || getReg(op2)==7) && getMod(op2)==2 && getRM(op2)==4) // /5 or /7, Full displacement, SIB
			instructionSize=7;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xF6) // F6 group
	{
		if (getReg(op2)==0||getReg(op2)==1) // /0 or /1, TEST Eb Ib
		{
			if (getMod(op2)==0 && getRM(op2)!=5 && getRM(op2)!=4) // No displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)==5) // Full displacement
					instructionSize=8;
				else // No displacement
					instructionSize=4;
			}
			else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute address
				instructionSize=7;
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=4;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=5;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=7;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=8;
			else if (getMod(op2)==3) // Direct register
				instructionSize=3;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else // F6 Eb
		{
			if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
				instructionSize=2;
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==3) // Direct register
				instructionSize=2;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}
	else if (op==0xF7) // F7 group
	{
		if (getReg(op2)==0||getReg(op2)==1) // /0 or /1, TEST Ev Iv
		{
			if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
				instructionSize=6;
			else if (getMod(op2)==0 && getRM(op2)==5) // Absolute address
				instructionSize=10;
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=7;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=8;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=10;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=11;
			else if (getMod(op2)==3) // Direct register
				instructionSize=6;
		}
		else // /2, /3, /4, /5 /6, or /7 (Ev)
		{
			if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)==5) // Full displacement
					instructionSize=7;
				else // No displacement
					instructionSize=3;
			}
			else if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
				instructionSize=2;
			else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
				instructionSize=3;
			else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
				instructionSize=4;
			else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
				instructionSize=6;
			else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
				instructionSize=7;
			else if (getMod(op2)==3) // Direct register
				instructionSize=2;
		}

		if (opSize && (getReg(op2)==0||getReg(op2)==1)) // For /0 or /1
			instructionSize-=2;
	}
	else if (op==0xD0 || op==0xFE) // Eb
	{
		if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0xFF && getReg(op2)!=3 && getReg(op2)!=5) // FF group, Ev instructions (extended by ModRM:Reg)
	{
		if (getMod(op2)==0 && getRM(op2)!=4 && getRM(op2)!=5) // No displacement, no SIB
			instructionSize=2;
		else if (getMod(op2)==0 && getRM(op2)==5) // Absolute memory address
			instructionSize=6;
		else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
		{
			uint8_t op3 = *(virtualImage+addr+2);
			if (getRM(op3)==5) // SIB w/ Full 4B displacement
				instructionSize=7;
			else // No displacement
				instructionSize=3;
		}
		else if (getMod(op2)==1 && getRM(op2)!=4) // 1B displacement, no SIB
			instructionSize=3;
		else if (getMod(op2)==1 && getRM(op2)==4) // 1B displacement, SIB
			instructionSize=4;
		else if (getMod(op2)==2 && getRM(op2)!=4) // Full displacement, no SIB
			instructionSize=6;
		else if (getMod(op2)==2 && getRM(op2)==4) // Full displacement, SIB
			instructionSize=7;
		else if (getMod(op2)==3) // Direct register
			instructionSize=2;
		else
			throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
	}
	else if (op==0xFF && (getReg(op2)==3 || getReg(op2)==5)) // FF group, Mv instructions (extended by ModRM:Reg)
	{
		throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);

		if (opSize)
			throw generateOpcodeErrorInfo("Operand-size override not implemented",addr);
	}

	// Extended two opcodes instructions
	if (op==0x0F)
	{
		uint8_t op3 = *(virtualImage+addr+2);
		if (op2>=0x80&&op2<=0x8F) // JXX Jv
		{
			instructionSize=6;
			if (opSize)
				instructionSize-=2;
		}
		else if (op2==0x77 || op2==0xA2 || (op2>=0xC8&&op2<=0xCF)) // CPUID or XXX Zv or control
			instructionSize=2;
		else if (op2==0xB6 || (op2==0xAE && getReg(op3)==3) || op2==0xBE || (op2>=0x90&&op2<=0x9F)) // XXX Gv Eb or XXX Eb or Md
		{
			if (getMod(op3)==0 && getRM(op3)!=4 && getRM(op3)!=5) // No displacement, no SIB
				instructionSize=3;
			else if (getMod(op3)==0 && getRM(op3)==5) // Absolute address
				instructionSize=7;
			else if (getMod(op3)==0 && getRM(op3)==4) // No displacement, SIB
			{
				uint8_t op4=*(virtualImage+addr+3);
				if (getRM(op4)!=5)
					instructionSize=4;
			}
			else if (getMod(op3)==1 && getRM(op3)!=4) // 1B displacement, no SIB
				instructionSize=4;
			else if (getMod(op3)==1 && getRM(op3)==4) // 1B displacement, SIB
				instructionSize=5;
			else if (getMod(op3)==2 && getRM(op3)!=4) // Full displacement, no SIB
				instructionSize=7;
			else if (getMod(op3)==2 && getRM(op3)==4) // Full displacement, SIB
				instructionSize=8;
			else if (getMod(op3)==3) // Direct register
				instructionSize=3;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else if (op2==0xB7 || op2==0xBF) // MOVZX Gv Ew
		{
			if (getMod(op3)==0 && getRM(op3)!=4 && getRM(op3)!=5) // No displacement, no SIB
				instructionSize=3;
			else if (getMod(op3)==0 && getRM(op3)==5) // Absolute address
				instructionSize=7;
			else if (getMod(op3)==0 && getRM(op3)==4) // No displacement, SIB
			{
				uint8_t op4=*(virtualImage+addr+3);
				if (getRM(op4)!=5) // No displacement
					instructionSize=4;
				else // Full displacement
					instructionSize=8;
			}
			else if (getMod(op3)==1 && getRM(op3)!=4) // 1B displacement, no SIB
				instructionSize=4;
			else if (getMod(op3)==1 && getRM(op3)==4) // 1B displacement, SIB
				instructionSize=5;
			else if (getMod(op3)==2 && getRM(op3)!=4) // Full displacement, no SIB
				instructionSize=7;
			else if (getMod(op3)==2 && getRM(op3)==4) // Full displacement, SIB
				instructionSize=8;
			else if (getMod(op3)==3) // Direct register
				instructionSize=3;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else if ((op2>=0x40 && op2<=0x4F) || (op2==0x3A&&op3==0x44) || op2==0x6E || op2==0x7E || op2==0xA5 || op2==0xAB
				|| op2==0xAD || op2==0xDB || op2==0xAF || op2==0xB1 || op2==0xB3 || op2==0xBB || op2==0xBC || op2==0xBD
				|| op2==0x6F || op2==0x7F || op2==0xC1 || op2==0xD4 || op2==0xEF || op2==0x66 || op2==0xFE || op2==0x11
				|| op2==0xF4 || (op2>=0x10 && op2<=0x17) || (op2>=0x51 && op2<=0x5F) || op2==0x28 || op2==0xD7
				|| op2==0x2A || op2==0x2D || op2==0x76 || op2==0xFB || op2==0xE6 || op2==0xF3 || op2==0xFA
				|| op2==0xEE || op2==0xDF
				|| op2==0xA3 || op2==0x2C) // Gv Ev or Ev Gv or Pq Ed or Vdq Ed or Pq Qq or Vdq Wdq or Gd Wsd or Vq Mq
		{
			if (getMod(op3)==0 && getRM(op3)==5) // Absolute address
				instructionSize=7;
			else if (getMod(op3)==0 && getRM(op3)==4) // No displacement, SIB
			{
				uint8_t op4=*(virtualImage+addr+3);
				if (getRM(op4)!=5) // No displacement
					instructionSize=4;
				else // Full displacement
					instructionSize=8;
			}
			else if (getMod(op3)==0 && getRM(op3)!=4 && getRM(op3)!=5) // No displacement, no SIB
				instructionSize=3;
			else if (getMod(op3)==1 && getRM(op3)!=4) // 1B displacement, no SIB
				instructionSize=4;
			else if (getMod(op3)==1 && getRM(op3)==4) // 1B displacement, SIB
				instructionSize=5;
			else if (getMod(op3)==2 && getRM(op3)!=4) // Full displacement, no SIB
				instructionSize=7;
			else if (getMod(op3)==2 && getRM(op3)==4) // Full displacement, SIB
				instructionSize=8;
			else if (getMod(op3)==3) // Direct register
				instructionSize=3;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else if (op2==0x70 || op2==0x73 || op2==0xBA || op2==0xA4 || op2==0xC2 || op2==0xC4 || op2==0xC5 || op2==0xC6
				|| op2==0xAC) // Ev Ib or Ev Gv Ib or Nq Ib or Udq Ib or Vps Wps Ib
		{
			if (getMod(op3)==0 && getRM(op3)!=4 && getRM(op3)!=5) // No displacement, no SIB
				instructionSize=4;
			else if (getMod(op2)==0 && getRM(op2)==4) // No displacement, SIB
			{
				uint8_t op3=*(virtualImage+addr+2);
				if (getRM(op3)==5) // Full displacement
					instructionSize=9;
				else // No displacement
					instructionSize=5;
			}
			else if (getMod(op2)==0 && getRM(op2)==5) // No displacement, absolute memory address
				instructionSize=8;
			else if (getMod(op3)==1 && getRM(op3)!=4) // 1B displacement, no SIB
				instructionSize=5;
			else if (getMod(op3)==1 && getRM(op3)==4) // 1B displacement, SIB
				instructionSize=6;
			else if (getMod(op3)==2 && getRM(op3)!=4) // Full displacement, no SIB
				instructionSize=8;
			else if (getMod(op3)==2 && getRM(op3)==4) // Full displacement, SIB
				instructionSize=9;
			else if (getMod(op3)==3) // Direct register
				instructionSize=4;
			else
				throw generateOpcodeErrorInfo("Opcode ModRM not implemented",addr);
		}
		else if (op2==0x01&&op3==0xD0) // XCR
			instructionSize=3;
	}

	// Now that we have the size, add the instruction
	if (instructionSize != 0)
	{
		if (pf1)		{addr--; instructionSize++;}
		if (pf2)		{addr--; instructionSize++;}
		if (opSize)		{addr--; instructionSize++;}
		if (adSize)		{addr--; instructionSize++;}
		addOpcodes(instruction,addr,instructionSize);
		code[addr]=instruction;
		return instructionSize;
	}
	else
	{
		throw generateOpcodeErrorInfo("Invalid opcode",addr);
		return 0;
	}
}
