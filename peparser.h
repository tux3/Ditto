#ifndef PEPARSER_H
#define PEPARSER_H

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string>
#include "peformat.h"
#include "relocation.h"

class PEParser
{
	public:
		PEParser(uint8_t*& Data, size_t& DataSize);
		PEParser(const PEParser&)=delete;
		~PEParser()=default;
		void operator=(const PEParser&)=delete;

		std::vector<std::string> getSectionNames();
		std::pair<uint8_t*,size_t> getSectionData(std::string sectionName);
		size_t getSectionRawSize(std::string sectionName);
		uint32_t getSectionRawAddr(std::string sectionName);
		size_t getSectionVirtualSize(std::string sectionName);
		uint32_t getSectionVirtualAddr(std::string sectionName);
        uint32_t getEntryPoint();
		uint32_t getRelEntryPoint();
		uint8_t*& getVirtualImage();
		std::pair<uint32_t,uint32_t> getSectionVirtualBounds(std::string sectionName);
		std::vector<std::pair<uint32_t,uint32_t>> getCodeSectionsVirtualBounds();
		uint32_t getImageBase();
		uint32_t getCodeBase();
		std::pair<uint8_t*,size_t> getData();
		void updateDataFromVirtualImage();
		uint32_t addSection(std::string name, size_t size, uint32_t flags);
		void expandLastSectionBy(size_t size);
		void setEntryPoint(uint32_t value);
		bool isLastSectionRECode();
		uint32_t getLastSectionEnd();
		//void readRelocations();
        //std::vector<Relocation> getRelocations();
	private:
	    uint8_t*& data; // May change at any time
		size_t& dataSize; // May change at any time
		uint8_t* virtualImage; // May change at any time
		size_t virtualImageSize; // May change at any time
		COFFHeader* coffHeader;
		PEOptHeader* peHeader;
		std::vector<SectionHeader*> sectionHeaders;
		std::vector<Relocation> relocs;
		//bool doneReadingRelocations; // True when we've read the relocations
};

#endif // PEPARSER_H
