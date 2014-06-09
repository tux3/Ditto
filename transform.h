#ifndef TRANSFORM_H
#define TRANSFORM_H

#include "disassembler.h"
#include "peparser.h"

class Transform
{
	public:
		Transform(Disassembler& disassembler, PEParser& Parser, uint8_t Rand);
		/// Substitutes instructions with equivalent instructions of the same size.
		/// @return The number of substitutions done
		unsigned substitute();
		/// Substitutes small sets of instructions with equivalent instructions of the same size.
		/// @return The number of substitutions done
		unsigned shuffle();
		/// Encrypts a section and move the entry point to a generated polymorphic decryptor.
		/// @return Id of the decryptor used, or 0 if a generic decryptor was used.
		unsigned short encryptSection(std::string sectionName);
	protected:
		/// Uses the rand probability given in the constructor
		bool getRandBool();
	private:
		Disassembler& disasm;
		PEParser& parser;
		uint8_t rand;
};

/**

TODO:
Ideas for transforms

- In-place subsitution
Replace instructions with equivalent instructions of the same size
- In-place advanced substitution
Replace small (2-4) sets of instructions with an equivalent set of the same size.(hard to find something to do)
- Shrink substition
Tries to find sets of instructions that can be replaced by a smaller equivalent.
- Shuffle substitution
Shuffle blocks of instructions that can be reordered safely
- ROP substitution
Tries to replace small blocks of instructions by a call to an existing equal block followed by a RET
- NOP
Simply insert no-operations, extended-NOPs, hintable NOPs, etc at safe places
- Block reordering
Tries to build a list of blocks with a single call entry point and no jumps, then reorder them randomly
- Anti-debug
Inserts anti-debugging instructions at fixed points, close to the start of the control flow
- Anti-sandbox
Insert ring3 "rare" instructions and check their result as an attempt to detect a potential sandbox
- Entry-point reordering
If possible, moves the entry point and the function around it before or after a random function
- Prefixes
Add unnecessary prefixes such as 0x66 or 0x67 where they have no effect, ALTER or TAKEN hints, etc
- Manual calls
Transform CALL instructions into manual pushes and jmps.
- Register shuffling
Tries to find blocks of code working with a paticular register, and make it work with another.
- Blending polymorphism
The entry point will unpack the whole program before running it. Statistically FUD.
- Function-level blending polymorphism
Functions will be unpacked before use, and repacked before returning. Statistically FUD.
- Data polymorphysm
Will encrypt the section with the name passed in argument with a simple XOR, decryptor is in its own section.

**/

#endif // TRANSFORM_H
