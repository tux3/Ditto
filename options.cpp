#include "options.h"
#include "error.h"
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <fstream>

using namespace std;

string argPath, argOut, argRandStr, argEncryptSectionName;
int argRand{65};
bool argSubstitute{false}, argShuffle{false};

bool parseArguments(int argc, char* argv[])
{
    char c;
	while ((c = getopt (argc, argv, "sSho:r:e:")) != -1)
         switch (c)
           {
            case 'h':
            cout << "Ditto, a generic metamorphic engine\nUsage : ditto [-hs] [-e s] [-r n] -o output input\n\n"
                    "-o f\tOutput file\n"
                    "-r n\tProbability, between 1 and 100, of each operations of the transforms. 65 by default.\n"
                    "-h  \tShow this help\n"
                    "-s  \tIn-place substitution:Replace instructions with equivalent instructions of the same size\n"
                    "-S  \tShuffle small blocks of instructions when their order isn't important.\n"
                    "-e s\tEncrypts the section s, the entry point will be moved to a polymorphic decryptor\n";
			exit(0);
            break;
			case 's':
            argSubstitute=true;
            break;
            case 'S':
            argShuffle=true;
            break;
            case 'o':
            argOut = optarg;
            break;
            case 'r':
            argRandStr = optarg;
            break;
            case 'e':
            argEncryptSectionName = optarg;
            break;
            case '?':
              if (optopt == 'o')
                fprintf (stderr, "Option -o requires an argument.\n");
			  else if (optopt == 'r')
                fprintf (stderr, "Option -r requires a numerical argument.\n");
			  else if (optopt == 'e')
                fprintf (stderr, "Option -e requires the name of a section.\n");
              else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c' or missing argument.\n", optopt);
              else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
              return false;
            default:
              return false;
            }
	if (optind < argc)
		argPath = argv[optind];
	else
	{
		cout << "Error: no input file\n";
		return false;
	}
	if (argOut.empty())
	{
		cout << "Error: no output file\n";
		return false;
	}
	if (!argRandStr.empty())
	{
		int result = atoi(argRandStr.c_str());
		if (result>=1 && result<=100)
			argRand=result;
		else
		{
			cout << "Error:Option -r requires a numerical argument between 1 and 100\n";
			return false;
		}
	}
	return true;
}
