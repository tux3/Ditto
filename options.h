#ifndef OPTIONS_H_INCLUDED
#define OPTIONS_H_INCLUDED

#include <string>

extern std::string argPath, argOut, argRandStr, argEncryptSectionName;
extern int argRand;
extern bool argSubstitute, argShuffle;

bool parseArguments(int argc, char* argv[]);

#endif // OPTIONS_H_INCLUDED
