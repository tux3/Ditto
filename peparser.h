#ifndef PEPARSER_H
#define PEPARSER_H

#include "objectparser.h"
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

class PEParser : public ObjectParser
{
	public:
		PEParser(uint8_t*& Data, size_t& DataSize);
		virtual ~PEParser()=default;
		virtual std::vector<std::string> getSectionNames();
		virtual std::pair<uint8_t*,size_t> getSectionData(std::string sectionName);
		virtual size_t getSectionRawSize(std::string sectionName);
		virtual uint32_t getSectionRawAddr(std::string sectionName);
		virtual size_t getSectionVirtualSize(std::string sectionName);
		virtual uint32_t getSectionVirtualAddr(std::string sectionName);
		virtual uint32_t getEntryPoint();
		virtual uint32_t getRelEntryPoint();
		virtual uint8_t*& getVirtualImage();
		virtual std::pair<uint32_t,uint32_t> getSectionVirtualBounds(std::string sectionName);
		virtual std::vector<std::pair<uint32_t,uint32_t>> getCodeSectionsVirtualBounds();
		virtual uint32_t getImageBase();
		virtual uint32_t getCodeBase();
		virtual void updateDataFromVirtualImage();
		virtual uint32_t addSection(std::string name, size_t size, uint32_t flags);
		virtual void setEntryPoint(uint32_t value);
		virtual std::pair<uint8_t*,size_t> getData();
	protected:
	private:
		COFFHeader* coffHeader;
		PEOptHeader* peHeader;
		std::vector<SectionHeader*> sectionHeaders;
};

#endif // PEPARSER_H
