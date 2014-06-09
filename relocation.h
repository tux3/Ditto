#ifndef RELOCATION_H_INCLUDED
#define RELOCATION_H_INCLUDED

enum RelocationType
{
    IMAGE_REL_BASED_ABSOLUTE=0,
    IMAGE_REL_BASED_HIGH=1,
    IMAGE_REL_BASED_LOW=2,
    IMAGE_REL_BASED_HIGHLOW=3,
    IMAGE_REL_BASED_HIGHADJ=4,
    IMAGE_REL_BASED_MIPS_JMPADDR=5, ///< Unused
    IMAGE_REL_BASED_SECTION=6, ///< Unused
    IMAGE_REL_BASED_REL32=7 ///< Unused
};

/// Describes a chunk (raw array) of relocations. Each relocation is 16bit (2B)
struct RelocationChunk
{
    uint32_t virtualAddress; ///< Start RVA this chunk's relocations apply to
    uint32_t sizeOfChunk; ///< Size in bytes of the chunk, header not included
};

struct Relocation
{
    uint16_t offset : 12;
    uint16_t type : 4; ///< Directly castable to a RelocationType
};

#endif // RELOCATION_H_INCLUDED
