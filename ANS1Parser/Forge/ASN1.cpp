/*
  ==============================================================================

    ASN1.cpp
    Created: 26 Jun 2022 10:56:45am
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "ASN1.h"

namespace Forge
{
namespace ASN1
{

void _checkBitsParam(int numBits)
{
    jassert( numBits == 8 || numBits == 16 || numBits == 24 || numBits == 32 );
}

juce::String derToOid(juce::String str)
{
//    var oid;
    juce::String oid;
    
    // wrap in buffer if needed
//    if(typeof bytes === 'string')
//    {
//        bytes = forge.util.createBuffer(bytes);
//    }
    auto stdString = str.toStdString();
    auto block = juce::MemoryBlock(stdString.data(), stdString.length());
    auto bytes = juce::MemoryInputStream(block, false);
    
    // first byte is 40 * value1 + value2
//    var b = bytes.getByte();
    auto b = bytes.readByte();
    
//    oid = Math.floor(b / 40) + '.' + (b % 40);
    oid << std::floor( static_cast<float>(b) / 40.f );
    oid << ".";
    oid << b % 40;
    
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
//    var value = 0;
    juce::uint64 value = 0;
//    while(bytes.length() > 0)
    while(! bytes.isExhausted() )
    {
//        b = bytes.getByte();
        b = bytes.readByte();
        value = value << 7;
        // not the last byte for the value
        if(b & 0x80)
        {
            value += (b & 0x7F);
        }
        else
        {
            // last byte
//            oid += '.' + (value + b);
            oid << ".";
            oid << (value + b);
            value = 0;
        }
    }
    
    return oid;
};

} //end namespace ASN1
} //end namespace Forge
