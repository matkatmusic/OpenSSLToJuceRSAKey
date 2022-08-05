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
    
    
    // wrap in buffer if needed
//    if(typeof bytes === 'string')
//    {
//        bytes = forge.util.createBuffer(bytes);
//    }
    auto stdString = str.toStdString();
    auto block = juce::MemoryBlock(stdString.data(), stdString.length());
    
    return derToOid(block);
}

juce::String derToOid(const juce::MemoryBlock& block)
{
    juce::String oid;
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

juce::var ASNObject::toVar() const
{
    juce::var v;
    
    v.append(static_cast<int>(tagClass));
    v.append(static_cast<int>(type));
    v.append(constructed);
    v.append(composed);
    
    if(! objectList.empty() )
    {
        juce::var objList;
        for( auto ptr : objectList )
        {
            objList.append(ptr->toVar());
        }
        
        v.append(objList);
    }
    else
    {
        v.append("empty object list");
    }
    
    if(! byteArray.isEmpty() )
    {
        v.append(byteArray);
    }
    else
    {
        v.append("empty byte array");
    }
    
    if(! bitStringContents.isEmpty() )
    {
        v.append(bitStringContents);
    }
    else
    {
        v.append("empty bit string contents");
    }
    
    return v;
}

ASNObject::Ptr ASNObject::fromVar(juce::var v)
{
    jassert(v.isArray());
    
    if(! v.isArray() )
    {
        return {};
    }
    
    Ptr ptr = new ASNObject();
    
    auto* arr = v.getArray();
    for( int i = 0; i < arr->size(); ++i )
    {
        auto& var = arr->getReference(i);
        if( i == 0 )
        {
            ptr->tagClass = static_cast<Class>(static_cast<int>(var));
        }
        else if( i == 1 )
        {
            ptr->type = static_cast<Type>(static_cast<int>(var));
        }
        else if( i == 2)
        {
            ptr->constructed = static_cast<bool>(var);
        }
        else if( i == 3 )
        {
            ptr->composed = static_cast<bool>(var);
        }
        else if( i == 4)
        {
            if( var.isString() && var == "empty object list" )
            {
                //do nothing.
            }
            else
            {
                jassert( var.isArray() );
                auto* objListArr = var.getArray();
                for( auto obj : *objListArr )
                {
                    ptr->objectList.push_back( fromVar(obj) );
                }
            }
        }
        else if( i == 5 )
        {
            if( var.isString() && var == "empty byte array")
            {
                //do nothing
            }
            else
            {
                auto* mb = var.getBinaryData();
                jassert(mb != nullptr);
                jassert( mb->getSize() != 0 );
                ptr->byteArray = *mb;
            }
        }
        else if( i == 6 )
        {
            if( var.isString() && var == "empty bit string contents" )
            {
                //do nothing
            }
            else
            {
                auto* mb = var.getBinaryData();
                jassert(mb != nullptr);
                jassert( mb->getSize() != 0 );
                ptr->bitStringContents = *mb;
            }
        }
    }
    
    return ptr;
}

juce::MemoryBlock oidToDer(juce::String oid)
{
//asn1.oidToDer = function(oid) {
    // split OID into individual values
//    var values = oid.split('.');
    auto values = juce::StringArray::fromTokens(oid, ".", "");
//    var bytes = forge.util.createBuffer();
    auto block = juce::MemoryBlock();
    auto bytes = juce::MemoryOutputStream(block, false);
    // first byte is 40 * value1 + value2
//    bytes.putByte(40 * parseInt(values[0], 10) + parseInt(values[1], 10));
    bytes.writeByte(40 + values[0].getIntValue() + values[1].getIntValue());
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
//    var last, valueBytes, value, b;
    bool last;
    std::vector<char> valueBytes;
    unsigned int value;
    int b;
    
//    for(var i = 2; i < values.length; ++i)
    for( int i = 2; i < values.size(); ++i )
    {
        // produce value bytes in reverse because we don't know how many
        // bytes it will take to store the value
        last = true;
//        valueBytes = [];
        valueBytes.clear();
//        value = parseInt(values[i], 10);
        value = values[i].getIntValue();
        
        do
        {
            b = value & 0x7F;
//            value = value >>> 7; //this is javascript unsigned shift right
            value = value >> 7;
            // if value is not last, then turn on 8th bit
            if(!last)
            {
                b |= 0x80;
            }
//            valueBytes.push(b);
            valueBytes.push_back(b);
            last = false;
        } while(value > 0);
        
        // add value bytes in reverse (needs to be in big endian)
//        for(var n = valueBytes.length - 1; n >= 0; --n)
        for( size_t n = valueBytes.size() - 1; n != 0; --n)
        {
//            bytes.putByte(valueBytes[n]);
            bytes.writeByte(valueBytes[n]);
        }
    }

    return block;
};

} //end namespace ASN1
} //end namespace Forge
