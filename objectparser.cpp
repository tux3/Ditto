#include "objectparser.h"
#include <iostream>

ObjectParser::ObjectParser(uint8_t* Data, size_t DataSize)
: data{Data}, dataSize{DataSize}
{
}
