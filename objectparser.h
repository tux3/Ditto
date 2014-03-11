#ifndef OBJECTPARSER_H
#define OBJECTPARSER_H

#include <stddef.h>
#include <vector>
#include <string>

/// Abstract object file parser, base class for PEParser, ELFParser, ...
class ObjectParser
{
	public:
		virtual std::vector<std::string> getSectionNames()=0; ///< Names of the object file's setions
		virtual std::pair<uint8_t*,size_t> getSectionData(std::string sectionName)=0; ///< Raw data in the section
		virtual uint32_t getEntryPoint()=0; ///< Offset to the entry point inside the virtual image
		virtual uint32_t getRelEntryPoint()=0; ///< Returns the offset of the entry relative to the start of the section
		/// Returns the virtual address of the start of the section
		virtual uint32_t getSectionVirtualAddr(std::string sectionName)=0;
		virtual uint32_t getSectionRawAddr(std::string sectionName)=0;
		virtual size_t getSectionVirtualSize(std::string sectionName)=0;
		virtual size_t getSectionRawSize(std::string sectionName)=0;
		/// Returns a complete image in memory loaded at the virtual offsets. This pointer may change at any time.
		virtual uint8_t*& getVirtualImage()=0;
		/// Returns a pair of the virtual start and ends of a section, offsets refer to the virtual image.
		virtual std::pair<uint32_t,uint32_t> getSectionVirtualBounds(std::string sectionName)=0;
		/// Returns a vector of virtual bounds for the executable sections. Offsets refer to the virtual image.
		virtual std::vector<std::pair<uint32_t,uint32_t>> getCodeSectionsVirtualBounds()=0;
		virtual uint32_t getImageBase()=0;
		virtual uint32_t getCodeBase()=0;
		virtual void updateDataFromVirtualImage()=0;
		/// Returns an offset to the start of the new section in the virtual image
		virtual uint32_t addSection(std::string name, size_t size, uint32_t flags)=0;
		/// Sets the entry point (in the virtual image) to the given value. No checking.
		virtual void setEntryPoint(uint32_t value)=0;
		virtual std::pair<uint8_t*,size_t> getData()=0;

	protected:
		ObjectParser(uint8_t*& Data, size_t& DataSize);

	protected:
		uint8_t*& data; // May change at any time
		size_t& dataSize; // May change at any time
		uint8_t* virtualImage; // May change at any time
		size_t virtualImageSize; // May change at any time
};

#endif // OBJECTPARSER_H
