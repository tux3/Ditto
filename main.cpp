#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <algorithm>
#include <unistd.h>

#include "objectparser.h"
#include "peparser.h"
#include "disassembler.h"
#include "transform.h"

using namespace std;

void exitWithError (string error)
{
	cout << error;
	exit(1);
}

void exitWithError()
{
	exitWithError("FAIL\nAborting...");
}

int main(int argc, char* argv[])
{
	// Parse arguments
	string argPath, argOut, argRandStr;
	int argRand=65;
	bool argSubstitute=false, argForce=false, argForceCode=false;
	char c;
	while ((c = getopt (argc, argv, "shfo:r:")) != -1)
         switch (c)
           {
            case 'h':
            cout << "Ditto, a generic metamorphic engine\nUsage : ditto [-hsfF] [-r n] -o output input\n\n\
-o f\tOutput file\n\
-r n\tProbability, between 1 and 100, of each operations of the transforms. 65 by default.\n\
-h  \tShow this help\n\
-s  \tIn-place subsitution:Replace instructions with equivalent instructions of the same size\n\
-f  \tForcefully continue, at the risk of generating an incorrect result.\n\
-F  \tForce the disassembler to treat everything as code, and try to read it.\n";
			exit(0);
            break;
			case 's':
            argSubstitute=true;
            break;
            case 'o':
            argOut = optarg;
            break;
            case 'r':
            argRandStr = optarg;
            break;
            case 'f':
            argForce = true;
            break;
            case 'F':
            argForceCode = true;
            break;
           case '?':
             if (optopt == 'o')
               fprintf (stderr, "Option -o requires an argument.\n");
			 else if (optopt == 'r')
               fprintf (stderr, "Option -r requires a numerical argument.\n");
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
             return 1;
           default:
             abort ();
           }
	if (optind < argc)
		argPath = argv[optind];
	else
	{
		cout << "Error: no input file\n";
		return 1;
	}
	if (argOut.empty())
	{
		cout << "Error: no output file\n";
		return 1;
	}
	if (!argRandStr.empty())
	{
		int result = atoi(argRandStr.c_str());
		if (result>=1 && result<=100)
			argRand=result;
		else
		{
			cout << "Error:Option -r requires a numerical argument between 1 and 100\n";
			exit(1);
		}
	}

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
	unique_ptr<ObjectParser> parser=nullptr;
	try // PE
	{
		cout << "PE...";
		unique_ptr<PEParser> peParser{new PEParser{data, dataSize}};
		cout << "OK"<<endl;
		parser=move(peParser);
	}
	catch (const char* e)
	{
		exitWithError(string("FAIL (")+e+")");
	}
	if (parser==nullptr)
		exitWithError("Error : Can't detect file type.\n");

	// Disassemble the code sections
	/** DONE;
	Modify the disassembler to take an EP pointing to the virtual image
	Modify the disassembler to take the whole virtual image, not just the .text section, then modify it to take
	the vector of the bounds of the executable sections instead of just the end of the section or of the image.
	Update isAddrInternal to check if the addr is within bounds of an executable section.
	**/
	/** TODO:
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
	**/
	cout << "Disassembling...";
	Disassembler* disasm;
	try {
	disasm=new Disassembler(*parser, argForce, argForceCode);
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
		trans = new Transform(*disasm,argRand); // The ctor performs the analysis
	}
	catch (const char* e) {
		exitWithError(string("FAIL (")+e+")\nAborting.\n");
	}
	cout << "OK\n";

	if (argSubstitute)
	{
		cout << "Substitute...";
		int nOps;
		try {
			nOps=trans->substitute();
		}
		catch (const char* e) {
			exitWithError(string("FAIL (")+e+")\nAborting.\n");
		}
		cout << "OK ("<<nOps<<" instructions)\n";
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
	fstream outFile;
	outFile.open(argOut.c_str(),ios_base::out | ios_base::binary | ios_base::trunc);
	if (!outFile.is_open())
		exitWithError();
	outFile.write((char*)data, dataSize);
	outFile.close();
	cout << "OK ("<<dataSize<<" bytes)\n";

	return 0;
}
