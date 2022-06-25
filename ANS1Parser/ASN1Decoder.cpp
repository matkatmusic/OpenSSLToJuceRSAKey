/*
  ==============================================================================

    ASN1Decoder.cpp
    Created: 25 Jun 2022 12:14:33pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "ASN1Decoder.h"

ASN1Tag::ASN1Tag(juce::InputStream* stream)
{
    jassert(stream != nullptr);
    jassert(!stream->isExhausted());
    
    auto buf = stream->readByte();
    tagClass = buf >> 6;
    tagConstructed = (buf & 0x20) != 0;
    tagNumber = buf & 0x1f;
    if( tagNumber == 0x1f ) //long tag
    {
        auto n = Int10();
        do
        {
            buf = stream->readByte();
            n.mulAdd(128, buf & 0x7F);
        }
        while (buf & 0x80 && !stream->isExhausted() );
        tagNumber = n.simplify();
    }
}

bool ASN1Tag::isEOC() const
{
    return tagClass == 0x00 && tagNumber == 0x00;
}

bool ASN1Tag::isUniversal() const
{
    return tagClass == 0x00;
}
//==============================================================================
//ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L494
juce::int64 ASN1Decoder::decodeLength(juce::InputStream& stream)
{
    juce::uint8 byte = stream.readByte();
    juce::uint64 buf = byte; //allows for 48-bit lengths
    auto len = buf & 0x7f;
    if( len == buf )
        return len;
    
    if( len == 0 )
        return -1;
    
    if( len > 6 )
    {
        //JS: throw "Length over 48 bits not supported at position " + (stream.pos - 1);
        jassertfalse;
        return -1;
    }
    
    buf = 0;
    for (int i = 0; i < len; ++i)
    {
        juce::uint8 val = stream.readByte();
        buf = (buf * 256) + val;
    }
    
    return buf;
}

//ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L528
ASN1::Ptr ASN1Decoder::decode(juce::MemoryInputStream& stream, int offset)
{
    auto streamStart = std::make_unique<juce::MemoryInputStream>(stream.getData(), stream.getDataSize(), true);
    streamStart->setPosition(stream.getPosition());
    auto tag = ASN1Tag(&stream);
    auto tagLen = stream.getPosition() - streamStart->getPosition();
    auto len = decodeLength(stream);
    auto start = stream.getPosition();
    auto header = start - streamStart->getPosition();
    auto sub = std::vector<ASN1::Ptr>();
    
    auto getSub = [&]()
    {
        if( len != -1 )
        {
            auto end = start + len;
            if( end > stream.getTotalLength() )
            {
                // JS: throw 'Container at offset ' + start +  ' has a length of ' + len + ', which is past the end of the stream';
                jassertfalse;
                return;
            }
            
            while( stream.getPosition() < end )
            {
                sub.push_back(decode(stream));
            }
            
            if( stream.getPosition() != end )
            {
                // JS: throw 'Content size is not correct for container at offset ' + start;
                jassertfalse;
                return;
            }
        }
        else
        {
            // undefined length
            for (;;)
            {
                auto s = decode(stream);
                if( s == nullptr )
                {
                    jassertfalse;
                    break;
                }
                if (s->tag.isEOC())
                {
                    break;
                }
                sub.push_back(s);
            }
            len = start - stream.getPosition();
        }
    };
    
    if (tag.tagConstructed)
    {
        getSub();
    }
    else if (tag.isUniversal() && ((tag.tagNumber == 0x03) || (tag.tagNumber == 0x04)))
    {
        // sometimes BitString and OctetString are used to encapsulate ASN.1
        if (tag.tagNumber == 0x03)
        {
            if( stream.readByte() != 0 )
            {
                //JS: throw "BIT STRINGs with unused bits cannot encapsulate.";
                jassertfalse;
            }
        }
        getSub();
        for( size_t i = 0; i < sub.size(); ++i )
        {
            if( sub[i]->tag.isEOC() )
            {
                //JS: throw 'EOC is not supposed to be actual content.';
                jassertfalse;
                sub.clear();
                break;
            }
        }
    }
    
    if( sub.empty() )
    {
        if( len == -1 )
        {
            // JS throw "We can't skip over an invalid tag with undefined length at offset " + start;
            jassertfalse;
            return {};
        }
        
        stream.setPosition(start + std::abs(len));
    }
    
    return new ASN1(std::move(streamStart), header, len, tag, tagLen, sub);
}
