#include "transform.h"
#include <list>
#include <iostream>

using namespace std;

unsigned Transform::shuffle()
{
	/** ideas go here
	Work on NOPs as a last resort. Normally we should ignore NOPs, but it's slow.
	We should build a list of the next 3 adjacent non-nop instructions.
	If they aren't adjacent, continue until they are.
	Every end of a loop, we remove the first item of the list, and add the next adjacent instruction

	We need to write a function getUsedRegister(instruction) wich returns the list of all the registers used
	If for example we push or read a value at [ESP], then ESP is affected. If we LEAVE, ESP and EBP are affected.

	Try to find shuffling on the 3 instructions first, if we can't, search on the two first only.
	If we don't NEED the three instructions to be independent to shuffle, then only use the first two, it's faster.

	If none of the 2 first instructions are not a JMP/CALL/etc or something dangerous,
	if the getUsedRegister of the two have a null intersection, shuffle the two and continue

	If the first two are OxC7 MOV Ev Iv with the same ModRM, shuffle the two.
	It's ok since they write to the same kind of destination, only the displacement/addr can change.
	**/
	unsigned nShuffles = 0;
	const std::map<uint32_t ,std::vector<uint8_t>> code = disasm.getCode();
	if (code.size() < 3)
		return 0;
	std::list<std::pair<uint32_t ,std::vector<uint8_t>>> curInss;
	for (std::pair<uint32_t ,std::vector<uint8_t>> ins : code)
	{
		uint8_t curInssSize = curInss.size();
		if (curInssSize<3)
		{
			curInss.push_back(ins);
			if (curInssSize<3)
				continue;
		}
		else
		{
			curInss.pop_front();
			curInss.push_back(ins);
		}

		// Check that addresses are continuous
		if ((++curInss.begin())->first != curInss.begin()->first + curInss.begin()->second.size())
			continue;

		if (curInss.back().first != (++curInss.begin())->first + (++curInss.begin())->second.size())
			continue;

		// If the first two are OxC7 MOV Ev Iv with the same ModRM, shuffle the two.
		if (curInss.begin()->second.size()>=2 && (++curInss.begin())->second.size()>=2)
			if (curInss.begin()->second[0]==0xC7 && (++curInss.begin())->second[0]==0xC7)
				if (curInss.begin()->second[1] == (++curInss.begin())->second[1])
				{
					// Swap instructions
					uint32_t addr1 = curInss.begin()->first;
					uint32_t addr2 = (++curInss.begin())->first;
					disasm.editInstruction(addr1, (++curInss.begin())->second);
					disasm.editInstruction(addr2, curInss.begin()->second);
					nShuffles++;

					// We're done with the two first instructions
					curInss.pop_front();
					curInss.pop_front();
					continue;

					// TODO: We should check that the two instructions dont write at addresses that overlap
				}
	}

	return nShuffles;
}
