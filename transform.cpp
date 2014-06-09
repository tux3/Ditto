#include "transform.h"
#include "peparser.h"
#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

Transform::Transform(Disassembler& disassembler, PEParser& Parser, uint8_t Rand)
: disasm(disassembler), parser(Parser), rand(Rand)
{
	srand(time(NULL));

	//disasm.analyze();
}

bool Transform::getRandBool()
{
	int r = ::rand()%100;
	return (r<rand);
}

unsigned short Transform::encryptSection(std::string sectionName)
{
	unsigned short decryptorUsed=0;
	// Returns with obfuscated rets and stack magic. Uses instructions inside constants.
	uint8_t codeObf[] = {0x68,0,0,0,0,0x68,0,0,0,0,0x66,0x58,0xBA,0x66,0x68,0,0,
							0xC3,0x8D,0x0D,0,0,0,0,0x8B,1,0x35,0,0,0,0,0x89,1,0x83,
							0xC1,4,0x8D,5,0,0,0,0,0x3B,0xC8,0x72,0xEA,0xEB,0xDD};

	// Returns with a plain jump
	uint8_t codeNormal[] = {0x8D,0x0D,0,0,0,0,0x8B,1,0x35,0,0,0,0,0x89,1,0x83,0xC1,4,
										0x8D,5,0,0,0,0,0x3B,0xC8,0x72,0xEA,0xE9,0,0,0,0};

	uint32_t key=(::rand()%0xEEEE) + ((::rand()%0xEEEE)<<16);
	uint32_t oldEP = parser.getEntryPoint();
	uint32_t imageBase = parser.getImageBase();
	pair<uint32_t,uint32_t> bounds = parser.getSectionVirtualBounds(sectionName);
	uint32_t dataStart = bounds.first+imageBase, dataEnd = bounds.second+imageBase;

	// Create section
	/// TODO: Only create a new section if the last section isn't code!
	uint32_t decryptorPos;
	if (parser.isLastSectionRECode())
	{
		cout << "Last section is RE code\n";
		decryptorPos = parser.getLastSectionEnd();
	}
	else
	{
		sectionName.insert(begin(sectionName),'D');
		sectionName.resize(8);
		decryptorPos = parser.addSection(sectionName,0,IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ_EXECUTE);
	}
	uint8_t*& virtualImage = parser.getVirtualImage();


	// Generate decryptor
	size_t decryptCodeSize;
	uint8_t* decryptCode;
	if (::rand()%2) // Use the decryptor with obfuscated ret to the old ep
	{
		decryptCodeSize = 48;
		uint32_t absOldEP = imageBase + oldEP;
		uint32_t absFirstRet = imageBase + decryptorPos+18;
		uint16_t random = ::rand()&0xFFFF;
		*(uint16_t*)(codeObf+1) = absFirstRet>>16;
		*(uint16_t*)(codeObf+3) = absOldEP>>16;
		*(uint16_t*)(codeObf+6) = random;
		*(uint16_t*)(codeObf+8) = absFirstRet&0xFFFF;
		*(uint16_t*)(codeObf+15) = absOldEP&0xFFFF;
		*(uint32_t*)(codeObf+20) = dataStart;
		*(uint32_t*)(codeObf+27) = key;
		*(uint32_t*)(codeObf+38) = dataEnd-3;
		decryptCode = codeObf;
		decryptorUsed=1;
	}
	else // Use the simple decryptor with plain jump to the old ep
	{
		decryptCodeSize = 33;
		*(uint32_t*)(codeNormal+2) = dataStart;
		*(uint32_t*)(codeNormal+9) = key;
		*(uint32_t*)(codeNormal+20) = dataEnd-3;
		*(uint32_t*)(codeNormal+29) = 0xFFFFFFFF - (decryptorPos+32-oldEP);
		decryptCode = codeNormal;
		decryptorUsed=2;
	}
	decryptCodeSize*=2;

	// Encrypt section
	parser.expandLastSectionBy(decryptCodeSize);
	for (uint32_t* i=(uint32_t*)(virtualImage+bounds.first); (uint8_t*)i<(virtualImage+bounds.second-3); ++i)
		*i ^= key;

	// Inject decryptor in new section
	for (uint8_t i=0; i<decryptCodeSize; ++i)
		*(virtualImage+decryptorPos+i)=decryptCode[i];

	// Change entry point
	parser.setEntryPoint(decryptorPos);

	/// TODO: If the section is not writable, we need to add a runtime permission change before the shellcode

	/// TODO: Overload substitute to take a reference to any vector of instructions and modify it.

	/// TODO: We'll want to make an USG thingy for the decryptor.
	/// We could generate random parts of the decryptor and link them together. For example have 10 different ways
	/// to jump back to the old EP, 5 different crypting algo (XOR, rolling XOR, XOR+ADD, ...), X ways to check
	/// Add a rand()%2 chanche that the decryptor runs from end to start instead of start to end
	/// if we reached the end of the data, X ways to load the data start ptr, etc
	/// Then select these parts at random and link them together.
	/// Each part should be able to link around/with the previous one.
	/// Then give the vector of instructions to substitude, advSubstiture and substitureRegisters, and write result.
	/// I need to ARMOR that fucking decryptor to death. Every single byte must be random and the positions too.
	/// We must be able to use different key sizes too, and replace the JB by something else like CMP and JNZ.
	/// We need the really everything to be different and undetectable without false positives on everything.

	/// We should scan the end of the section before generating the decryptor. Often the end is padded with 0s,
	/// we should skip the last contigous block of 0s and only crypt until this block.

	/// We NEED to parse the damn relocations and imports.

	/// TODO: BUG: Dammit the crypter on .data causes everything serious to fail ! Including blender, NPP, Bitcoin, etc.

	return decryptorUsed;
}
