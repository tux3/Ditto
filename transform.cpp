#include "transform.h"
#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

Transform::Transform(Disassembler& disassembler, uint8_t Rand)
: disasm(disassembler), rand(Rand)
{
	srand(time(NULL));

	//disasm.analyze();
}

bool Transform::getRandBool()
{
	int r = ::rand()%100;
	return (r<rand);
}
