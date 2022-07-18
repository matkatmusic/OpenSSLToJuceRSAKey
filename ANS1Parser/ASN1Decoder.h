/*
  ==============================================================================

    ASN1Decoder.h
    Created: 25 Jun 2022 12:14:33pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>

//ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/int10.js
struct Int10
{
    static constexpr juce::int64 max = 10'000'000'000'000;
    std::vector<juce::int64> buf;
    
    Int10(juce::int64 val = 0)
    {
        buf.push_back(val);
    }
    void mulAdd(juce::int64 m, juce::int64 c)
    {
        auto& b = buf;
        auto l = b.size();
        size_t i = 0;
        juce::int64 t;
        for (; i < l; ++i)
        {
            t = b[i] * m + c;
            if (t < max)
            {
                c = 0;
            }
            else
            {
                //
                c = std::floor(static_cast<double>(t) / static_cast<double>(max));
                t -= c * max;
            }
            b[i] = t;
        }
        if (c > 0)
        {
            b[i] = c;
        }
    }
    
    auto simplify() const
    {
        return buf.front();
    }
};

//ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L508
struct ASN1Tag
{
    int tagClass = 0;
    bool tagConstructed = false;
    juce::int64 tagNumber = 0;
    
    ASN1Tag(juce::InputStream* stream = nullptr);
    
    bool isEOC() const;
    
    bool isUniversal() const;
};

//ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L324
struct ASN1 : juce::ReferenceCountedObject
{
    using Ptr = juce::ReferenceCountedObjectPtr<ASN1>;

    /**
        The stream to read from.
     To read the stream, use the 'header' and 'length' members. and read the stream into a juce::MemoryBlock
     e.g.:
     @code
  
     ASN1::Ptr sequence = new ASN1(...);
     juce::MemoryBlock exponentBlock;
     exponentBlock.setSize(sequence->length);
     sequence->stream->setPosition(sequence->stream->getPosition() + sequence->header);
     sequence->stream->read(exponentBlock.getData(), static_cast<int>(sequence->length));
     @endcode
     */
    std::unique_ptr<juce::MemoryInputStream> stream;
    juce::int64 header = 0;
    juce::int64 length = 0;
    ASN1Tag tag;
    juce::int64 tagLen = 0;
    
    ///the array of sub sequences in this particular node.
    std::vector<Ptr> sub;
    
    ASN1() = default;
    
    ASN1(std::unique_ptr<juce::MemoryInputStream>&& stream_,
         juce::int64 header_,
         juce::int64 length_,
         ASN1Tag tag_,
         juce::int64 tagLen_,
         std::vector<Ptr> sub_) :
    stream(std::move(stream_)),
    header(header_),
    length(length_),
    tag(tag_),
    tagLen(tagLen_),
    sub(sub_)
    {
        
    }
};

struct ASN1Decoder
{
    /**
    Converts a PEM-formatted public or private key stored in a juce::MemoryInputStream into an ASN1 object.
    ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L528
     */
    static ASN1::Ptr decode(juce::MemoryInputStream& stream, int offset = 0);
    
private:
    //ported from: https://github.com/lapo-luchini/asn1js/blob/trunk/asn1.js#L494
    static juce::int64 decodeLength(juce::InputStream& stream);
    
    ASN1Decoder() = delete;
};

struct ASN1Encoder
{
//    static juce::int32 derToInteger(juce::MemoryBlock bytes)
//    {
//        
//    }
//    static juce::int32 derToInteger(juce::String bytes)
//    {
//        
//    }
    
//    static juce::MemoryBlock toDer(ASN1::Ptr obj)
//    {
//        juce::MemoryBlock bytes;
//        using Byte = juce::uint8;
//        Byte b1 = static_cast<Byte>(obj->tag.tagClass) | static_cast<Byte>(obj->type);
//        
//    }
};
