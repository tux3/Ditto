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
		virtual uint8_t* getEntryPoint()=0; ///< Points to the entry point inside the virtual image
		virtual uint32_t getRelEntryPoint()=0; ///< Returns the offset of the entry relative to the start of the section
		/// Returns the virtual address of the start of the section
		virtual uint8_t* getSectionVirtualAddr(std::string sectionName)=0;
		virtual uint8_t* getSectionRawAddr(std::string sectionName)=0;
		virtual size_t getSectionVirtualSize(std::string sectionName)=0;
		virtual size_t getSectionRawSize(std::string sectionName)=0;
		/// Returns a complete image in memory, loaded at its virtual addresses (not in it's own addr space, obviously).
		virtual uint8_t* getVirtualImage()=0;
		/// Returns a pair of the virtual start and ends of a section, this points inside the virtual image.
		virtual std::pair<uint8_t*,uint8_t*> getSectionVirtualBounds(std::string sectionName)=0;
		/// Returns a vector of virtual bounds for the executable sections. Pointers refer to the virtual image.
		virtual std::vector<std::pair<uint8_t*,uint8_t*>> getCodeSectionsVirtualBounds()=0;
		virtual uint32_t getImageBase()=0;
		virtual uint32_t getCodeBase()=0;
		virtual void updateDataFromVirtualImage()=0;

	protected:
		ObjectParser(uint8_t* Data, size_t DataSize);

	protected:
		uint8_t* data;
		size_t dataSize;
		uint8_t* virtualImage;
		size_t virtualImageSize;
};

#endif // OBJECTPARSER_H
