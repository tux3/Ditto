Ditto
=====

Generic Metamorphic/Substitution Engine

<h2>Not even in Alpha</h2>
This project is still under developpment, and not all of the features described may work.<br/>
No binairies will be provided until it reaches a stable-ish point where you can safely assume that any resulting binary will reproduce the exact behavior of the original, unless unsafe options are explicitely used.<br/>
The design and features can still change at any given time.

<h2>What it is, what it does</h2>
It takes an executable file in input, tries do rewrite and reorder it on a higher level, then outputs a file that produces the same observable behavior, but with a content that might look completely different in, for example, a hex editor.<br/>
It does not need to be integrated in a project to work, Ditto is a standalone executable.
But if embedded in a self-replicating program, it is effectively possible to create a different 'generation' on every iteration.

<h2>(Planned) features</h2>
Simple substitutions, adding or removing no-ops, semi-randomization of the metadata, and reordering of small blocks of instructions are the fastest and simplest operations.<br/>
Reordering of the jump/call flow, register shuffling, ROP substitutions, merging, reordering and obfuscation of data are all more complex, and they require a complete analysis of the code with the use of relocations, as any error in the analysis could completely break the output.<br/>
It is also possible to encrypt sections and generate a polymorphic decryption rountine that replaces the entry point, but this is only an option and not recommended.<br/>
The combination of those options should be able to 'randomize' most parts of a binary.

<h2>How does it work ?</h2>
Ditto will make use of relocations to assist the analysis, and will even require a .reloc section for the more advanced options.<br/>
A a built-in disassembler with support for most of the x86 instruction set, including x87 and the various extensions (SSE, SSE2, SSE2, MMX, etc) is used to first separate code into instructions and mark the known references to data.<br/>
Optional analysis passes then build data structures containing the map of branches with their destinations, cross-references, jump flow, higher-level data structures, and known independent blocks of code.<br/>
Then the optional transforms will work on the higher-level representations of the binary successively.<br/>
Finally the virtual image and then the raw image are rebuilt from the instructions and metadata and the result is written to the output file.

<h2>But why ?</h2>
Self-modifying code is fascinating in its own way. I wrote this mostly to learn, to acquire experience, but also as a proof of concept.
And open-source engines with those features are still somewhat rare, Z0mbie's work comes to mind, but it is perhaps not as maintanable and might not be trying to achieve the same goal.

<h4>Where's the source code</h4>
I'll probably publish it soon-ish, it is currently ~3000 lines of C++ and implements only the disassembler, basic analysis and simple transforms at the moment. It is also in serious need of refactoring and cleaning.
