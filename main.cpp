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
		exitWithError("Can't detect file type. Aborting.");

    // Get .text section
    cout << "Parsing sections...";
    vector<string> sectionNames = parser->getSectionNames();
    //for (string& s : sectionNames) cout <<s<<"\n";
    pair<uint8_t*,size_t> code;
    unsigned long entryPoint;
    if (find(begin(sectionNames),end(sectionNames),string(".text"))!=end(sectionNames))
	{
		code = parser->getSectionData(".text");
		entryPoint = parser->getRelEntryPoint();
		long absEntryPoint = parser->getEntryPoint();
		if (absEntryPoint<(int)parser->getSectionRawAddr(".text")
			|| absEntryPoint>=(int)(parser->getSectionRawAddr(".text")+parser->getSectionRawSize(".text")))
			exitWithError("FAIL (Entry point not in .text section)\nAborting.\n");
	}
	else
		exitWithError("FAIL (Can't find code section)\nAborting.\n");
	cout << "OK\n";
	uint8_t* vStart = parser->getSectionVirtualAddr(".text");

	// Disassemble the .text section
	cout << "Disassembling...";
	Disassembler* disasm;
	try {
	disasm=new Disassembler((uint8_t*)code.first, code.second, entryPoint, vStart, *parser, argForce, argForceCode);
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

	cout << "Writing result...";
	std::map<uint8_t* ,std::vector<uint8_t>> result = disasm->getCode();
	if (disasm->getDataSize() != code.second)
		exitWithError("FAIL (Section resizing not implemented)\n");
	for (const std::pair<uint8_t* ,std::vector<uint8_t>>& ins : result)
	{
		uint8_t* addr=ins.first-code.first+data+(long)parser->getSectionRawAddr(".text");
		for (uint8_t i=0; i<ins.second.size(); i++)
			*(addr+i)=ins.second[i];
	}
	fstream outFile;
	outFile.open(argOut.c_str(),ios_base::out | ios_base::binary | ios_base::trunc);
	if (!outFile.is_open())
		exitWithError();
	outFile.write((char*)data, dataSize);
	outFile.close();
	cout << "OK ("<<disasm->getDataSize()-code.second+dataSize<<" bytes)\n";

	return 0;
}
