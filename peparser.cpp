#include "peparser.h"
#include <iostream>
#include <algorithm>
#include <mem.h>

using namespace std;

PEParser::PEParser(uint8_t* Data, size_t DataSize)
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
		sectionHeaders.push_back(sectionHeader);

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
		memcpy(vStart, pStart, loadSize);
	}
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

uint8_t* PEParser::getEntryPoint()
{
	// Find the section containing the entry point
	// substract virtual offset from RVA entry point to get physical entry point
	unsigned long entry = peHeader->addressOfEntryPoint;
	for (SectionHeader* h : sectionHeaders)
	{
		unsigned long start = h->virtualAddress;
		unsigned long limit = start+h->virtualSize;
		if (entry>start && entry<limit)
			return virtualImage + entry;
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

uint8_t* PEParser::getSectionRawAddr(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (uint8_t*)(*it)->rawDataOffset;
}

size_t PEParser::getSectionRawSize(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (*it)->rawDataSize;
}

uint8_t* PEParser::getSectionVirtualAddr(std::string sectionName)
{
	uint8_t* vAddr;
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	vAddr=(uint8_t*)(*it)->virtualAddress;

	return vAddr;
}

size_t PEParser::getSectionVirtualSize(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	return (*it)->virtualSize;
}

uint8_t* PEParser::getVirtualImage()
{
	return virtualImage;
}

std::pair<uint8_t*,uint8_t*> PEParser::getSectionVirtualBounds(std::string sectionName)
{
	auto it = find_if(begin(sectionHeaders), end(sectionHeaders),
					[sectionName](SectionHeader* h){return string(string(h->name,8).c_str())==sectionName;});
    if (it==end(sectionHeaders))
		throw std::invalid_argument("Section does not exist");
	uint8_t* start=virtualImage+(*it)->virtualAddress;
	uint8_t* end=start+(*it)->virtualSize;
	return pair<uint8_t*,uint8_t*>(start,end);
}

uint32_t PEParser::getImageBase()
{
	return peHeader->imageBase;
}

uint32_t PEParser::getCodeBase()
{
	return peHeader->baseOfCode;
}

std::vector<std::pair<uint8_t*,uint8_t*>> PEParser::getCodeSectionsVirtualBounds()
{
	vector<std::pair<uint8_t*,uint8_t*>> bounds;
    for (SectionHeader* h : sectionHeaders)
	{
		if (h->characteristics & IMAGE_SCN_CNT_CODE)
		{
			cout << "CODE SECTION:"<<string(h->name,8)<<"\n";
			size_t size = min(h->virtualSize, h->rawDataSize);
			uint8_t* virtualStart=(uint8_t*)virtualImage+h->virtualAddress;
			bounds.push_back(pair<uint8_t*,uint8_t*>{virtualStart,virtualStart+size});
		}
	}
	return bounds;
}

void PEParser::updateDataFromVirtualImage()
{
	// Copy the headers back
	size_t headersSize=(uint8_t*)(sectionHeaders.back()+1) - data;
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
