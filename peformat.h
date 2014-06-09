#ifndef PEFORMAT_H_INCLUDED
#define PEFORMAT_H_INCLUDED

#include <stdint.h>

struct DOSHeader
{
    char signature[2]; // Must be "MZ" 3C
    short lastsize;
    short nblocks;
    short nreloc;
    short hdrsize;
	short minalloc;
    short maxalloc;
    uint16_t ss;
    uint16_t sp;
    short checksum;
    uint16_t ip;
    uint16_t cs;
    short relocpos;
    short noverlay;
    short reserved1[4];
    short oem_id;
    short oem_info;
    short reserved2[10];
    uint32_t e_lfanew;
};

struct COFFHeader
{
	short machine;
	short numberOfSections;
	int timeDateStamp;
	int pointerToSymbolTable;
	int numberOfSymbols;
	short sizeOfOptionalHeader;
	short characteristics;
};

struct DataDirectory // RVA and size of the data
{
   long VirtualAddress;
   long Size;
};

struct PEOptHeader
{
	short signature; //decimal number 267.
	char majorLinkerVersion;
	char minorLinkerVersion;
	long sizeOfCode;
	long sizeOfInitializedData;
	long sizeOfUninitializedData;
	long addressOfEntryPoint;  //The RVA of the code entry point
	long baseOfCode;
	long baseOfData;
	long imageBase;
	long sectionAlignment;
	long fileAlignment;
	short majorOSVersion;
	short minorOSVersion;
	short majorImageVersion;
	short minorImageVersion;
	short majorSubsystemVersion;
	short minorSubsystemVersion;
	long reserved;
	long sizeOfImage;
	long sizeOfHeaders;
	long checksum;
	short subsystem;
	short dllCharacteristics;
	long sizeOfStackReserve;
	long sizeOfStackCommit;
	long sizeOfHeapReserve;
	long sizeOfHeapCommit;
	long loaderFlags;
	long numberOfRvaAndSizes; // Number of data_directory
	DataDirectory dataDirectory[16];     // Can have any number of elements, matching the number in NumberOfRvaAndSizes.
};

struct SectionHeader
{
	char name[8];
	uint32_t virtualSize;			// Address of the section in memory
	uint32_t virtualAddress;		// RVA of the section in memory
	uint32_t rawDataSize;			// Size on disk
	uint32_t rawDataOffset;			// Offset on disk. Multiple of the alignment.
	uint32_t relocationsOffset;		// Offset of relocations on disk. Null for executables, used in OBJs.
	uint32_t lineNumbersOffset; 	// Offest of line numbers on disk.
	uint16_t numberOfRelocations;	// Used in OBJs, null in executables
	uint16_t numberOfLineNumbers;	// Number of line numbers at the given offset
	uint32_t characteristics;		// Flags (see IMAGE_SCN_ defines below)
};

enum imageSectionCharacteristics
{
	IMAGE_SCN_CNT_CODE=0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA=0x00000040,
	IMAGE_SCN_MEM_READ_EXECUTE = 0x60000000
};

#endif // PEFORMAT_H_INCLUDED
