#include "peparser.h"
#include <iostream>
#include <algorithm>
#include <mem.h>

using namespace std;

PEParser::PEParser(uint8_t*& Data, size_t& DataSize)
: ObjectParser(Data, DataSize)
{
	//DOS header
    if (dataSize < sizeof(DOSHeader))
		throw "Too small";
	if (data[0]!='M'||data[1]!='Z')
		throw "Wrong DOS signature";

	// COFF header (and PE Magic)
	size_t peMagicOffset = reinterpret_cast<DOSHeader*>(data)->e_lfanew;
	if (dataSize < peMagicOffset+4+sizeof(COFFHeader))
		throw "Too small";
	uint8_t* peMagic = data+peMagicOffset;
	if (peMagic[0]!='P'||
		peMagic[1]!='E'||peMagic[2]!='\0'||peMagic[3]!='\0')
		throw "Wrong PE signature";
	coffHeader = reinterpret_cast<COFFHeader*>(peMagic+4);
	if (coffHeader->machine != 0x14C) // i386
		throw "Not i386";
	if ((unsigned short)coffHeader->sizeOfOptionalHeader < sizeof(PEOptHeader))
		throw "Optional PE header too small";
	if (dataSize < peMagicOffset+4+sizeof(COFFHeader)+coffHeader->sizeOfOptionalHeader)
		throw "Too small";
	if (coffHeader->characteristics&0x2 && !coffHeader->characteristics&0x2000) // File is a executable and not a DLL
		throw "Not an executable or a DLL";

	// PE (optional) header
	peHeader = reinterpret_cast<PEOptHeader*>((char*)coffHeader+sizeof(COFFHeader));
    if (peHeader->signature != 0x10B) // PE opt header magic
		throw "Wrong optional PE header signature";
	if (peHeader->subsystem!=2&&peHeader->subsystem!=3)
		throw "Subsystem is not console and not GUI";

	unsigned short nSections = coffHeader->numberOfSections;
	sectionHeaders.reserve(nSections);
	SectionHeader* sectionHeader = reinterpret_cast<SectionHeader*>(peHeader+1);
	for (unsigned short i=0; i<nSections; ++i, ++sectionHeader)
	{
		//cout << "Header off : "<<hex<<(uint32_t)sectionHeader-(uint32_t)data<<dec<<endl;
		sectionHeaders.push_back(sectionHeader);
	}

	// Compute size of virtual image
	size_t headersSize=(uint8_t*)(sectionHeaders.back()+1) - data;
	virtualImageSize=headersSize;
	for (SectionHeader* h : sectionHeaders)
	{
		size_t sectionEnd = h->virtualAddress+h->virtualSize;
		if (sectionEnd > virtualImageSize)
			virtualImageSize=sectionEnd;
	}

	// Load virtual image
	virtualImage = new uint8_t[virtualImageSize];
	memcpy(virtualImage, data, headersSize);
	for (SectionHeader* h : sectionHeaders)
	{
		uint8_t* pStart = data+h->rawDataOffset;
		uint8_t* vStart = virtualImage+h->virtualAddress;
		size_t loadSize = min(h->rawDataSize, h->virtualSize);
		memcpy(((uint8_t*)h)-(uint32_t)data+(uint32_t)virtualImage, h, sizeof(SectionHeader));
		memcpy(vStart, pStart, loadSize);
	}

	// Rebase our various pointers on the virtual image
	for (uint8_t i=0; i<sectionHeaders.size(); ++i)
		sectionHeaders[i] = (SectionHeader*)((uint8_t*)sectionHeaders[i] + (uint32_t)virtualImage - (uint32_t)data);
	coffHeader = (COFFHeader*)((uint8_t*)coffHeader + (uint32_t)virtualImage - data);
	peHeader = (PEOptHeader*)((uint8_t*)peHeader+ (uint32_t)virtualImage - data);
}

std::vector<std::string> PEParser::getSectionNames()
{
	std::vector<std::string> names;
	names.reserve(sectionHeaders.size());
	for (auto sectionHeader : sectionHeaders)
	{
		string name(sectionHeader->name,8);
		name.erase(find_if(name.rbegin(),name.rend(),not1(ptr_fun<int,int>(std::isspace))).base(),end(name));
		name=string(name.c_str());
		names.push_back(name);
	}
	return names;
}

std::pair<uint8_t*,size_t> PEParser::getSectionData(std::string sectionName)
{
    auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");

//	vector<uint8_t> sectionData;
	SectionHeader* header = *it;
	//if (header->virtualSize < header->rawDataSize)
	//	cout << "WARNING: Virtual size is smaller by 0x"<<hex<<(int)header->rawDataSize-(int)header->virtualSize<<dec<<" bytes\n";
//	uint8_t* start = (uint8_t*)data+header->rawDataOffset;
	size_t size = min(header->rawDataSize, header->virtualSize);
	if (size > dataSize)
		throw std::out_of_range("Section limit is after end of data");
//	for (uint8_t* c=start; c<limit; ++c)
//		sectionData.push_back(*c);

	return pair<uint8_t*,size_t>(data+header->rawDataOffset, size);

//	return sectionData;
}

uint32_t PEParser::getEntryPoint()
{
	// Find the section containing the entry point
	// substract virtual offset from RVA entry point to get physical entry point
	unsigned long entry = peHeader->addressOfEntryPoint;
	for (SectionHeader* h : sectionHeaders)
	{
		unsigned long start = h->virtualAddress;
		unsigned long limit = start+h->virtualSize;
		if (entry>=start && entry<limit)
			return entry;
	}
	throw "Can't find the section containing the entry point";
}

uint32_t PEParser::getRelEntryPoint()
{
	// Find the section containing the entry point
	// substract virtual offset from RVA entry point to get physical entry point
	unsigned long entry = peHeader->addressOfEntryPoint;
	for (SectionHeader* h : sectionHeaders)
	{
		unsigned long start = h->virtualAddress;
		unsigned long limit = start+h->virtualSize;
		if (entry>=start && entry<limit)
		{
			//cout<<"EP is in "<< h->name<<"\n";
			return entry - h->virtualAddress;
		}
	}
	throw "Can't find the section containing the entry point";
}

uint32_t PEParser::getSectionRawAddr(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (uint32_t)(*it)->rawDataOffset;
}

size_t PEParser::getSectionRawSize(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (*it)->rawDataSize;
}

uint32_t PEParser::getSectionVirtualAddr(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (uint32_t)(*it)->virtualAddress;
}

size_t PEParser::getSectionVirtualSize(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (*it)->virtualSize;
}

uint8_t*& PEParser::getVirtualImage()
{
	return virtualImage;
}

std::pair<uint32_t,uint32_t> PEParser::getSectionVirtualBounds(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	uint32_t start=(*it)->virtualAddress;
	uint32_t end=start+(*it)->virtualSize;
	return pair<uint32_t,uint32_t>(start,end);
}

uint32_t PEParser::getImageBase()
{
	return peHeader->imageBase;
}

uint32_t PEParser::getCodeBase()
{
	return peHeader->baseOfCode;
}

std::vector<std::pair<uint32_t,uint32_t>> PEParser::getCodeSectionsVirtualBounds()
{
	vector<std::pair<uint32_t,uint32_t>> bounds;
    for (SectionHeader* h : sectionHeaders)
	{
		if (h->characteristics & IMAGE_SCN_CNT_CODE)
		{
			//cout << "CODE SECTION:"<<string(h->name,8)<<"\n";
			size_t size = min(h->virtualSize, h->rawDataSize);
			uint32_t virtualStart=h->virtualAddress;
			bounds.push_back(pair<uint32_t,uint32_t>{virtualStart,virtualStart+size});
		}
	}
	return bounds;
}

void PEParser::updateDataFromVirtualImage()
{
	// Copy the headers back
	size_t headersSize=((uint8_t*)(sectionHeaders.back()+1)) - virtualImage;
	memcpy(data, virtualImage, headersSize);

	// Copy the sections back
	for (SectionHeader* h : sectionHeaders)
	{
		uint8_t* pStart = data+h->rawDataOffset;
		uint8_t* vStart = virtualImage+h->virtualAddress;
		size_t loadSize = min(h->rawDataSize, h->virtualSize);
		memcpy(pStart, vStart, loadSize);
	}
}

void PEParser::setEntryPoint(uint32_t value)
{
	peHeader->addressOfEntryPoint = value;
}

pair<uint8_t*,size_t> PEParser::getData()
{
	return pair<uint8_t*,size_t>(data,dataSize);
}

uint32_t PEParser::addSection(std::string name, size_t size, uint32_t flags)
{
	/// TODO: BUG: We fail to start with INVALID_IMAGE_FORMAT when we re-encrypt an encrypted file.
	/// Perhaps it's because when we add the second section, we need to update the headers size value
	/// Sounds like that's the problem. But if we want to update the headers size value
	/// we need to move every section's raw start by fileAlignment, wich also means reallocing again

	/// TODO: When we create a section, the start needs to be aligned, but the size can be whatever apparently.
	/// Don't set a hueg size if you don't need it.

	/// TODO: If the last section is a code section, instead of adding a new section the user of this function
	/// should resize the last section and add his code at the end.
	/// Could make a function extendLastSectionBy(uint32 size);
	uint32_t alignedRawStart = dataSize;
	if (alignedRawStart % peHeader->fileAlignment)
		alignedRawStart += peHeader->fileAlignment - dataSize%peHeader->fileAlignment;
	uint32_t alignedVStart = virtualImageSize;
	if (alignedVStart % peHeader->sectionAlignment)
		alignedVStart += peHeader->sectionAlignment - virtualImageSize%peHeader->sectionAlignment;

	uint32_t alignedRawEnd = alignedRawStart + size;
	//if (alignedRawEnd % peHeader->fileAlignment)
	//	alignedRawEnd += peHeader->fileAlignment - alignedRawEnd%peHeader->fileAlignment;
	uint32_t alignedVEnd = alignedVStart + size;
	//if (alignedVEnd % peHeader->sectionAlignment)
	//	alignedVEnd += peHeader->sectionAlignment - alignedVEnd%peHeader->sectionAlignment;

	// Check if there's room
	size_t newHeadersSize=(uint8_t*)(sectionHeaders.back()+2) - virtualImage;
	if (newHeadersSize >= sectionHeaders[0]->rawDataOffset)
		throw "Not enough room for new section header";

	// Realloc
	uint8_t* oldImageAddr = virtualImage;
	data = (uint8_t*)realloc(data, alignedRawEnd);
	virtualImage = (uint8_t*)realloc(virtualImage,alignedVEnd);

	// Rebase headers
	for (uint8_t i=0; i<sectionHeaders.size(); ++i)
		sectionHeaders[i] = (SectionHeader*)((uint32_t)sectionHeaders[i] - (uint32_t)oldImageAddr + (uint32_t)virtualImage);
	coffHeader = (COFFHeader*)((uint32_t)coffHeader - (uint32_t)oldImageAddr + (uint32_t)virtualImage);
	peHeader = (PEOptHeader*)((uint32_t)peHeader - (uint32_t)oldImageAddr + (uint32_t)virtualImage);

	// Create section header
	// (the section data isn't in the virtual image, since we can't realloc without invalidating all pointers)
	// (when we copy back to the raw data, we'll still copy the section, even if it's not really in the virtual image)
	SectionHeader* newHeader = (sectionHeaders.back()+1);
	newHeader->characteristics=flags;
	newHeader->lineNumbersOffset=0;
	strncpy(newHeader->name, name.c_str(), 8);
	newHeader->numberOfLineNumbers=0;
	newHeader->numberOfRelocations=0;
	newHeader->rawDataOffset=alignedRawStart;
	newHeader->rawDataSize=size;//alignedRawEnd - alignedRawStart;
	newHeader->relocationsOffset=0;
	newHeader->virtualAddress=alignedVStart;
	newHeader->virtualSize=size;//alignedVEnd - alignedVStart;
	sectionHeaders.push_back(newHeader);

	// Update metadata
	coffHeader->numberOfSections++;
	peHeader->sizeOfImage += alignedVEnd - alignedVStart;
	if (flags & IMAGE_SCN_CNT_CODE)
	{
		peHeader->sizeOfCode += alignedVEnd - alignedVStart;
		peHeader->sizeOfInitializedData += alignedVEnd - alignedVStart;
	}

	// Update sizes
	dataSize = alignedRawEnd;
	virtualImageSize = alignedVEnd;

	return (uint32_t)newHeader->virtualAddress;
}

void PEParser::expandLastSectionBy(size_t size)
{
	// Realloc
	uint8_t* oldImageAddr = virtualImage;
	data = (uint8_t*)realloc(data, dataSize+size);
	virtualImage = (uint8_t*)realloc(virtualImage,virtualImageSize+size);

	// Rebase headers
	for (uint8_t i=0; i<sectionHeaders.size(); ++i)
		sectionHeaders[i] = (SectionHeader*)((uint32_t)sectionHeaders[i] - (uint32_t)oldImageAddr + (uint32_t)virtualImage);
	coffHeader = (COFFHeader*)((uint32_t)coffHeader - (uint32_t)oldImageAddr + (uint32_t)virtualImage);
	peHeader = (PEOptHeader*)((uint32_t)peHeader - (uint32_t)oldImageAddr + (uint32_t)virtualImage);

	// Modify section header
	// Assuming that the section with the last header is the section at the end of the file
	SectionHeader* header = sectionHeaders.back();
	header->rawDataSize+=size;
	header->virtualSize+=size;

	// Update metadata
	peHeader->sizeOfImage += size;
	if (header->characteristics & IMAGE_SCN_CNT_CODE)
	{
		peHeader->sizeOfCode += size;
		peHeader->sizeOfInitializedData += size;
	}

	// Update sizes
	dataSize += size;
	virtualImageSize += size;
}

bool PEParser::isLastSectionRECode()
{
	// Assuming that the section with the last header is the section at the end of the file
	SectionHeader* header = sectionHeaders.back();
	uint32_t flags = IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ_EXECUTE;
	if ((header->characteristics & flags) == flags)
		return true;
	return false;
}

uint32_t PEParser::getLastSectionEnd()
{
	// Assuming that the section with the last header is the section at the end of the file
	SectionHeader* header = sectionHeaders.back();
	return header->virtualAddress + header->virtualSize;
}
