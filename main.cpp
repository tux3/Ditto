#include <fstream>
#include <memory>
#include <sstream>
#include <algorithm>
#include <iostream>

#include "objectparser.h"
#include "peparser.h"
#include "disassembler.h"
#include "transform.h"
#include "options.h"
#include "error.h"

using namespace std;

int main(int argc, char* argv[])
{
	if (!parseArguments(argc, argv))
        return 1;

	// Read file
	cout << "Reading "<<argPath<<"...";
	fstream argFile;
	argFile.open(argPath.c_str(),ios_base::in | ios_base::binary | ios_base::ate);
	if (!argFile.is_open())
		exitWithError();
	size_t dataSize = argFile.tellg();
	uint8_t* data = new uint8_t[dataSize];
	argFile.seekg(0,ios_base::beg);
	argFile.read((char*)data, dataSize);
	argFile.close();
	cout<<"OK ("<<dataSize << " bytes)\n";

	// Detect file type
	cout<<"Detecting file type :\n";
	PEParser* parser = nullptr;
	try // PE
	{
		cout << "PE...";
		parser = new PEParser{data, dataSize};
		cout << "OK"<<endl;
	}
	catch (const char* e)
	{
		exitWithError(string("FAIL (")+e+")");
	}
	if (parser==nullptr)
		exitWithError("Error : Can't detect file type.\n");

    // Read the relocations


	// Disassemble the code sections
	/** DONE;
	Modify the disassembler to take an EP pointing to the virtual image
	Modify the disassembler to take the whole virtual image, not just the .text section, then modify it to take
	the vector of the bounds of the executable sections instead of just the end of the section or of the image.
	Update isAddrInternal to check if the addr is within bounds of an executable section.
	**/
	/** TODO:
	Okay, we really need to read the damn relocations. LordPE can list them for reference.
	WinMD5 has relocations, tons of them.
	Relocations could be pointing to data or code, but at first we should just assume it's data unless we can prove it's code.
	We should run the relocation analysis before disassembling, so we know where not to go.
	If in the code we land on a point that is targeted by a relocation, we return. This could be data.
	Then after we're done doing the initial disassembly, we take a look at the relocs again.
	If we find a valid function start pointed by a reloc, we can mark it as "unknown", else mark it as "might be data".
	Now we look at all the unknown landing points and do a strict thorought analysis.
    If we're not reasonably sure it's code, we mark as might be data.

	We can search for signatures (such as push ebp/mov ebp,esp) and mark them for analysis.
	If we find those in the .text section, they are unlikely to be data.
	Do the dynamic analysis in another class and as a runtime option
	The dynamic analysis should be able to find data and code being referenced from the known code, we want to
	keep track of both. We should have a vector of known data references, like we have a vector of branches.
	The data structure should contain a set of instructions referencing it, a pointer to the data, and the size.
	When we modify/remove/add an instruction, we need to invalidate part of those data structures.
	We can rebuild the data structures after running updataVirtualImageFromInstructions() and re-analyzing the image.

	We should mark the ExitProcess function. Every function that always call ExitProcess should be marked as noreturn.
	This way if we reach a call to a noreturn function, we can stop instead of risking reading garbage or data

	We should probably implement data reference detection directly into the disassembler. For example if we see
	MOV REG, 0xXXXXXXXX, and 0xXXXXXXXX is an internal address, this is very likely data.
	For example B8 XXXXXXXX is sometimes used to load an address into EAX.
	We should do a test run, detect some of those, and see if all the results we get are data.
	=> The test run is definitely an improvement, because now we don't crash on WinMD5, but it's also WRONG.
	=> It's terribly wrong, we get false positives ! There are hardcoded function pointers that are moved into
	=> registers and we shouldn't mark them as data or we'll skip a large part of the code.
	=> That said, it's safer to skip part of the code, rather than reading data as code and later modifying it.
	==> Make a compromise. Instead of having the set dataRefs, make it the
	==> map<uint8_t, enum detectedType> refedAddrs. When we find an explicit JMP/CALL to this address, mark it in
	==> refedAddrs as code. If we find an instruction refering to an address, if it's not already marked as code, mark
	==> it as possibleData. This way function pointers still work, since they reference the same addr that is
	==> explicitely branched to elsewhere. If it's not explicitely branched to, then we wouldn't find it anyway.
	==> We should probably only check if we're about to read data after a jump or call, since data isn't going to
	==> appear in the middle of valid non-branching instructions.
	===> Now, right now we need to check every instruction whether or not we're landing on data.
	===> There might be a noreturn call with no references to the byte immediatly following it, but references later.
	====> There's also the problem of being aligned with the data. If the data is referenced at 0x2 and we start
	====> reading at 0x1, we'll never land exactly on the start of the data reference.

	=> Try to grep for 0x558BEC ou 0x5589E5 (push ebp, mov ebp, esp)
	=> See in olly if there are no false positives
	=> We hopefully shouldn't find too many false positives, since most of .text is supposed to be code, not data.
	=> Anyway, this should be an option not by default since it's dangerous.
	==> Grep with olly first to see what the results are.
	===> Maybe see if we can find a cleanup, or if there is a way to search for the cleanup.
	=> Read the imports table, and grep for calls to imports

	=> Option to randomize/anonymize the metadata. 0 the checksum, fill the VERSIONINFO, add noise to the icon, change timestamp, etc
	**/
	cout << "Disassembling...";
	Disassembler* disasm;
	try {
	disasm=new Disassembler(*parser);
	}
	catch (const char* e) {
		exitWithError(string("FAIL (")+e+")\nAborting.\n");
	}
	{
		unsigned nIns = disasm->getCode().size();
		cout << "OK ("<<nIns<<" instructions)\n";
	}


	// Run transforms
	cout << "Analysis...";
	Transform* trans;
	try {
		trans = new Transform(*disasm,*parser,argRand); // The ctor performs the analysis
	}
	catch (const char* e) {
		exitWithError(string("FAIL (")+e+")\nAborting.\n");
	}
	cout << "OK (disabled)\n";

	if (argSubstitute)
	{
		cout << "Substitute...";
		int nOps;
		try {
			nOps=trans->substitute();
			cout << "OK ("<<nOps<<" instructions)\n";
		}
		catch (const char* e) {
			exitWithError(string("FAIL (")+e+")\nAborting.\n");
		}
	}

	if (argShuffle)
	{
		cout << "Shuffle...";
		int nOps;
		try {
			nOps=trans->shuffle();
			cout << "OK ("<<nOps<<" shuffles)\n";
		}
		catch (const char* e) {
			exitWithError(string("FAIL (")+e+")\nAborting.\n");
		}
	}

	if (!argEncryptSectionName.empty())
	{
		cout << "Encrypting...";
		unsigned short decryptorUsed;
		try {
			decryptorUsed=trans->encryptSection(argEncryptSectionName);
		}
		catch (const char* e) {
			exitWithError(string("FAIL (")+e+")\nAborting.\n");
		}
		if (decryptorUsed)
			cout << "OK (decryptor "<<decryptorUsed<<")\n";
		else
			cout << "OK\n";
	}

	cout << "Rebuilding...";
	/** DONE:
	/// Have the disassembler implement a updataVirtualImageFromInstructions()
	/// Have the ObjectParser implement a updateDataFromVirtualImage() that memcpy back the headers and sections.
	**/
	/// TODO:
	/// We still don't handle changing the size, since we can't safely rebuild without relocations, or without
	/// being absolutely positive we decoded all the instructions/data references and can fix them.
	/// Then directly write the data buffer.
	disasm->updateVirtualImageFromInstructions();
	parser->updateDataFromVirtualImage();
	pair<uint8_t*,size_t> newData = parser->getData();
	fstream outFile;
	outFile.open(argOut.c_str(),ios_base::out | ios_base::binary | ios_base::trunc);
	if (!outFile.is_open())
		exitWithError("Failed to open output file");
	outFile.write((char*)newData.first, newData.second);
	outFile.close();
	cout << "OK ("<<dataSize<<" bytes)\n";

	return 0;
}
