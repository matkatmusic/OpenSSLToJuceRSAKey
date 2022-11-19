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
namespace V2
{
juce::var fromDer(const juce::MemoryBlock& bytes, juce::NamedValueSet options)
{
    using NV = juce::NamedValueSet::NamedValue;
    if( options.isEmpty())
    {
        options = {
            NV("strict", true),
            NV("parseAllBytes", true),
            NV("decodeBitStrings", true)
        };
    }
    
    if(! options.contains("strict") )
    {
        options.set("strict", true);
    }
    if(! options.contains("parseAllBytes") )
    {
        options.set("parseAllBytes", true);
    }
    if(! options.contains("decodeBitStrings") )
    {
        options.set("decodeBitStrings", true);
    }
    
    DBG( bytes.getSize() );
//    // wrap in buffer if needed
//    if(typeof bytes === 'string')
//    {
//        bytes = forge.util.createBuffer(bytes);
//    }
//    console.log(bytes.data.length);
//    var byteCount = bytes.length();
    /*
     _fromDer uses a byte buffer, which acts like a juce::InputStream.
     internally that byte buffer class uses a 'read' pointer.
     use juce::MemoryInputStream since you're working with a juce::MemoryBlock
     */
    
    juce::MemoryInputStream byteStream(bytes, false);
    auto len = byteStream.getNumBytesRemaining();
    
    auto value = _fromDer(byteStream, len, 0, options);
    if( options["parseAllBytes"].equalsWithSameType(true) && ! byteStream.isExhausted() )
    {
//      var error = new Error('Unparsed DER bytes remain after ASN.1 parsing.');
//      error.byteCount = byteCount;
//      error.remaining = bytes.length();
//      throw error;
        DBG( "Unparsed DER bytes remain after ASN.1 parsing." );
        DBG( "byteCount remaining: " << byteStream.getNumBytesRemaining() );
        jassertfalse;
        return {};
    }
    return value;
}

juce::var _fromDer(juce::MemoryInputStream& bytes,
                             juce::int64 remaining,
                             int depth,
                             juce::NamedValueSet options)
{
    using NV = juce::NamedValueSet::NamedValue;
    // temporary storage for consumption calculations
    //
    // minimum length for ASN.1 DER structure is 2
    V1::_checkBufferLength(bytes, remaining, 2);                                        //_checkBufferLength(bytes, remaining, 2);
                                                                                        //
    DBG("_fromDer( remaining: " << remaining << ", depth: " << depth << ", bytes: )");  //console.log("_fromDer( remaining: %d, depth: %d, bytes: )", remaining, depth );
    auto pos = bytes.getPosition();                                                     //var pos = bytes.read;
    {
        juce::MemoryBlock mb(remaining);
        juce::MemoryOutputStream mos(mb, false);
        mos.writeFromInputStream(bytes, remaining);
        mos.flush();
        DBG( juce::String::toHexString(mb.getData(),                                    //console.log(forge.util.binary.hex.encode(bytes.getBytes(remaining)));
                                       mb.getSize(),
                                       0) );
    }
    bytes.setPosition(pos);                                                             //bytes.read = pos;
    // get the first byte                                                               //// get the first byte
    juce::uint8 b1;
    auto numRead = bytes.read(&b1, 1);                                                  //var b1 = bytes.getByte();
    if( numRead != 1 )
    {
        jassertfalse;
        return {};
    }
    // consumed one byte                                                                //// consumed one byte
    remaining--;                                                                        //remaining--;
                                                                                        //
    // get the tag class                                                                //// get the tag class
    Class tagClass = static_cast<Class>(b1 & 0xc0);                                     //var tagClass = (b1 & 0xC0);
                                                                                        //
    // get the type (bits 1-5)                                                          //// get the type (bits 1-5)
    Type type = static_cast<Type>(b1 & 0x1f);                                           //var type = b1 & 0x1F;
                                                                                        //
    // get the variable value length and adjust remaining bytes                         //// get the variable value length and adjust remaining bytes
    auto start = bytes.getNumBytesRemaining();                                          //start = bytes.length();
    auto length = V1::_getValueLength(bytes, remaining);                                //var length = _getValueLength(bytes, remaining);
    remaining -= start - bytes.getNumBytesRemaining();                                  //remaining -= start - bytes.length();
                                                                                        //
    // ensure there are enough bytes to get the value
    if( length > remaining )                                                            //if(length !== undefined && length > remaining)
    {                                                                                   //{
        if(options["strict"].equalsWithSameType(true))                                  //    if(options.strict)
        {                                                                               //    {
            DBG( "Too few bytes to read ASN.1 value." );                                //        var error = new Error('Too few bytes to read ASN.1 value.');
            DBG( "available: " << bytes.getNumBytesRemaining() );                       //        error.available = bytes.length();
            DBG( "remaining: " << remaining );                                          //        error.remaining = remaining;
            DBG( "requested: " << length );                                             //        error.requested = length;
            jassertfalse; return {};                                                    //        throw error;
        }                                                                               //    }
        //Note: be lenient with truncated values and use remaining state bytes
        length = remaining;                                                             //    length = remaining;
    }                                                                                   //}
                                                                                        //
    // value storage                                                                    //// value storage
    juce::var value;                                                                    //var value;
                                                                                        // // possible BIT STRING contents storage
    juce::MemoryBlock bitStringContents;                                                //var bitStringContents;
                                                                                        //
    // constructed flag is bit 6 (32 = 0x20) of the first byte                          //// constructed flag is bit 6 (32 = 0x20) of the first byte
    bool constructed = ((b1 & 0x20) == 0x20);                                           //var constructed = ((b1 & 0x20) === 0x20);
    if(constructed)                                                                     //if(constructed)
    {                                                                                   //{
        // parse child asn1 objects from the value                                      //    // parse child asn1 objects from the value
        value = juce::Array<juce::var>();                                               //    value = [];
        if(length == -1)                                                                //    if(length === undefined)
        {                                                                               //    {
            // asn1 object of indefinite length, read until end tag//                   // asn1 object of indefinite length, read until end tag
            for(;;)                                                                     //        for(;;)
            {                                                                           //        {
                V1::_checkBufferLength(bytes, remaining, 2);                            //            _checkBufferLength(bytes, remaining, 2);
                auto pos = bytes.getPosition();
                juce::uint16 twoBytes = bytes.readShortBigEndian();
                bytes.setPosition(pos);
                if(twoBytes == 0)                                                       //            if(bytes.bytes(2) === String.fromCharCode(0, 0))
                {                                                                       //            {
                    bytes.readShortBigEndian();                                         //                bytes.getBytes(2);
                    remaining -= 2;                                                     //                remaining -= 2;
                    break;                                                              //                break;
                }                                                                       //            }
                start = bytes.getNumBytesRemaining();                                   //            start = bytes.length();
                DBG( "creating value from push(_fromDer()) with indefinite length");    //            console.log( "creating value from push(_fromDer()) with indefinite length");
                value.append(_fromDer(bytes, remaining, depth + 1, options));           //            value.push(_fromDer(bytes, remaining, depth + 1, options));
                remaining -= start - bytes.getNumBytesRemaining();                      //            remaining -= start - bytes.length();
            }                                                                           //        }
        }                                                                               //    }
        else                                                                            //    else
        {                                                                               //    {
            // parsing asn1 object of definite length                                   //        // parsing asn1 object of definite length
            while(length > 0)                                                           //        while(length > 0)
            {                                                                           //        {
                start = bytes.getNumBytesRemaining();                                   //            start = bytes.length();
                DBG( "creating value from push(_fromDer()) with definite length");      //            console.log( "creating value from push(_fromDer()) with definite length");
                value.append(_fromDer(bytes, length, depth + 1, options));              //            value.push(_fromDer(bytes, length, depth + 1, options));
                remaining -= start - bytes.getNumBytesRemaining();                      //            remaining -= start - bytes.length();
                length -= start - bytes.getNumBytesRemaining();                         //            length -= start - bytes.length();
            }                                                                           //        }
        }                                                                               //    }
    }                                                                                   //}
    //
    // if a BIT STRING, save the contents including padding
    if((value.isUndefined() || value.isVoid()) &&                                       //if(value === undefined &&
       tagClass == ASN1::Class::UNIVERSAL &&                                            //tagClass === asn1.Class.UNIVERSAL &&
       type == ASN1::Type::BITSTRING)                                                   //type === asn1.Type.BITSTRING)
    {                                                                                   //{
        auto pos = bytes.getPosition();
        juce::MemoryOutputStream mos(bitStringContents, false);
        mos.writeFromInputStream(bytes, length);                                        //    bitStringContents = bytes.bytes(length);
        bytes.setPosition(pos);
    }                                                                                   //}
                                                                                        //
                                                                                        // determine if a non-constructed value should be decoded as a composed
                                                                                        // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
                                                                                        // can be used this way.
    if((value.isUndefined() || value.isVoid()) &&                                       //if(value === undefined &&
       options["decodeBitStrings"].equalsWithSameType(true) &&                          // options.decodeBitStrings &&
       tagClass == ASN1::Class::UNIVERSAL &&                                            //   tagClass === asn1.Class.UNIVERSAL &&
                                                                                        // FIXME: OCTET STRINGs not yet supported here
                                                                                        // .. other parts of forge expect to decode OCTET STRINGs manually
       (type == ASN1::Type::BITSTRING /*|| type === asn1.Type.OCTETSTRING*/) &&         //   (type === asn1.Type.BITSTRING /*|| type === asn1.Type.OCTETSTRING*/) &&
       length > 1)                                                                      //   length > 1)
    {                                                                                   //{
        // save read position                                                           //    // save read position
        auto savedRead = bytes.getPosition();                                           //    var savedRead = bytes.read;
        auto savedRemaining = remaining;                                                //    var savedRemaining = remaining;
        juce::uint8 unused = 0;                                                         //    var unused = 0;
        if(type == ASN1::Type::BITSTRING)                                               //    if(type === asn1.Type.BITSTRING)
        {                                                                               //    {
                                                                                                /* The first octet gives the number of bits by which the length of the
                                                                                                 bit string is less than the next multiple of eight (this is called
                                                                                                 the "number of unused bits").
                                                                                                 The second and following octets give the value of the bit string
                                                                                                 converted to an octet string. */
            V1::_checkBufferLength(bytes, remaining, 1);                                //        _checkBufferLength(bytes, remaining, 1);
            unused = bytes.readByte();                                                  //        unused = bytes.getByte();
            remaining--;                                                                //        remaining--;
        }                                                                               //    }
                                                                                        //    // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
        if(unused == 0)                                                                 //    if(unused === 0)
        {                                                                               //    {
            //try                                                                       //        try
            {                                                                           //        {
                // attempt to parse child asn1 object from the value                    //            // attempt to parse child asn1 object from the value
                // (stored in array to signal composed value)                           //            // (stored in array to signal composed value)
                start = bytes.getNumBytesRemaining();                                   //            start = bytes.length();
                auto subOptions = juce::NamedValueSet(                                  //            var subOptions =
                {                                                                       //            {
                    // enforce strict mode to avoid parsing ASN.1 from plain data       //                // enforce strict mode to avoid parsing ASN.1 from plain data
                    NV("strict", true),                                                 //            strict: true,
                    NV("decodeBitStrings", true)                                        //            decodeBitStrings: true
                });                                                                     //            };
                auto composed = _fromDer(bytes, remaining, depth + 1, subOptions);      //            var composed = _fromDer(bytes, remaining, depth + 1, subOptions);
                auto used = start - bytes.getNumBytesRemaining();                       //            var used = start - bytes.length();
                remaining -= used;                                                      //            remaining -= used;
                if(type == ASN1::Type::BITSTRING)                                       //            if(type == asn1.Type.BITSTRING)
                {                                                                       //            {
                    used++;                                                             //                used++;
                }                                                                       //            }
    //
                // if the data all decoded and the class indicates UNIVERSAL or         //            // if the data all decoded and the class indicates UNIVERSAL or
                // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object  //            // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
                auto tc = static_cast<Class>(static_cast<int>(composed["tagClass"]));   //            var tc = composed.tagClass;
                if(used == length &&                                                    //            if(used === length &&
                   (tc == ASN1::Class::UNIVERSAL || tc == ASN1::Class::CONTEXT_SPECIFIC))//              (tc === asn1.Class.UNIVERSAL || tc === asn1.Class.CONTEXT_SPECIFIC))
                {                                                                       //            {
                    DBG( "creating value = [composed];");                               //                console.log( "creating value = [composed];");
                    value = juce::Array<juce::var>();                                   //                value = [composed];
                    value.append(composed);
                }                                                                       //            }
            }                                                                           //        }
            //catch(ex)                                                                 //        catch(ex)
            {                                                                           //        {
            }                                                                           //        }
        }                                                                               //    }
        if(value.isUndefined() || value.isVoid())                                       //    if(value === undefined)
        {                                                                               //    {
            // restore read position                                                    //        // restore read position
            bytes.setPosition(savedRead);                                               //        bytes.read = savedRead;
            remaining = savedRemaining;                                                 //        remaining = savedRemaining;
        }                                                                               //    }
    }                                                                                   //}
                                                                                        //
    if(value.isUndefined() || value.isVoid())                                           //if(value === undefined)
    {                                                                                   //{
        // asn1 not constructed or composed, get raw value                              //    // asn1 not constructed or composed, get raw value
        // TODO: do DER to OID conversion and vice-versa in .toDer?                     //    // TODO: do DER to OID conversion and vice-versa in .toDer?
                                                                                        //
        if(length == -1)                                                                //    if(length === undefined)
        {                                                                               //    {
            if(options["strict"].equalsWithSameType(true))                              //        if(options.strict)
            {                                                                           //        {
                DBG( "Non-constructed ASN.1 object of indefinite length.");             //            throw new Error('Non-constructed ASN.1 object of indefinite length.');
                jassertfalse;
            }                                                                           //        }
            // be lenient and use remaining state bytes                                 //        // be lenient and use remaining state bytes
            length = remaining;                                                         //        length = remaining;
        }                                                                               //    }
                                                                                        //
        if(type == ASN1::Type::BMPSTRING)                                               //    if(type === asn1.Type.BMPSTRING)
        {                                                                               //    {
            auto tempStr = juce::String();                                              //        value = '';
            DBG( "creating value from String.fromCharCode(bytes.getInt16());");         //        console.log( "creating value from String.fromCharCode(bytes.getInt16());");
            for(; length > 0; length -= 2)                                              //        for(; length > 0; length -= 2)
            {                                                                           //        {
                V1::_checkBufferLength(bytes, remaining, 2);                            //            _checkBufferLength(bytes, remaining, 2);
                auto shortBE = bytes.readShortBigEndian();
                auto utf16 = juce::CharPointer_UTF16( &shortBE );
                auto utf16Str = juce::String(utf16);
                tempStr += utf16Str;                                                    //            value += String.fromCharCode(bytes.getInt16());
                remaining -= 2;                                                         //            remaining -= 2;
            }                                                                           //        }
            value = tempStr;
        }                                                                               //    }
        else                                                                            //    else
        {                                                                               //    {
            juce::MemoryBlock mb;
            {
                juce::MemoryOutputStream mos(mb, false);
                mos.writeFromInputStream(bytes, length);
            }
            DBG( "creating value from bytes.getBytes(" << length << ")");               //        console.log( `creating value from bytes.getBytes(${length})`);
            value = mb;                                                                 //        value = bytes.getBytes(length);
            remaining -= length;                                                        //        remaining -= length;
        }                                                                               //    }
    }                                                                                   //}
    //
    // console.log( "_fromDer() final 'value' before asn1.create():  " );               //// console.log( "_fromDer() final 'value' before asn1.create():  " );
    // varPrinter(value);                                                               //// varPrinter(value);
                                                                                        //
    // add BIT STRING contents if available                                             //// add BIT STRING contents if available
    juce::NamedValueSet asn1Options;
    if(! bitStringContents.isEmpty() )                                                  //var asn1Options = bitStringContents === undefined ? null :
    {                                                                                   //{
        asn1Options.set("bitStringContents", bitStringContents);                        //    bitStringContents: bitStringContents
    }                                                                                   //};
                                                                                        //
    if( value.isVoid() )
    {
        jassertfalse;
    }
    // create and return asn1 object                                                    //// create and return asn1 object
    return create(tagClass, type, constructed, value, asn1Options);                     //return asn1.create(tagClass, type, constructed, value, asn1Options);
#if false
    using NV = juce::NamedValueSet::NamedValue;
    // minimum length for ASN.1 DER structure is 2
    V1::_checkBufferLength(bytes, remaining, 2);
    
//    console.log("_fromDer( remaining: %d, depth: %d, bytes: )", remaining, depth );
    DBG("_fromDer( remaining: " << remaining << ", depth: " << depth << ", bytes: )");
//    var pos = bytes.read;
    auto pos = bytes.getPosition();
//    console.log(forge.util.binary.hex.encode(bytes.getBytes(remaining)));
    {
        juce::MemoryBlock mb(remaining);
        juce::MemoryOutputStream mos(mb, false);
        mos.writeFromInputStream(bytes, remaining);
        mos.flush();
        DBG( juce::String::toHexString(mb.getData(), mb.getSize(), 0) );
    }
//    bytes.read = pos;
    bytes.setPosition(pos);
    // get the first byte
    juce::uint8 b1;
    auto numRead = bytes.read(&b1, 1);
    if( numRead != 1 )
    {
        jassertfalse;
        return {};
    }
    // consumed one byte
    remaining--;
    
    // get the tag class
    Class tagClass = static_cast<Class>(b1 & 0xc0);
    
    // get the type (bits 1-5)
    Type type = static_cast<Type>(b1 & 0x1f);
    
    // get the variable value length and adjust remaining bytes
    auto start = bytes.getNumBytesRemaining();
    auto length = V1::_getValueLength(bytes, remaining);
    remaining -= start - bytes.getNumBytesRemaining();
    
    // ensure there are enough bytes to get the value
    if( length > remaining )
    {
        if(options["strict"].equalsWithSameType(true))
        {
            DBG( "Too few bytes to read ASN.1 value." );
            DBG( "available: " << bytes.getNumBytesRemaining() );
            DBG( "remaining: " << remaining );
            DBG( "requested: " << length );
        }
        // Note: be lenient with truncated values and use remaining state bytes
        length = remaining;
    }
    
    // value storage
//    var value;
    juce::var value;
    // possible BIT STRING contents storage
//    var bitStringContents;
    juce::MemoryBlock bitStringContents;
    
    // constructed flag is bit 6 (32 = 0x20) of the first byte
    bool constructed = ((b1 & 0x20) == 0x20);
    if(constructed)
    {
        // parse child asn1 objects from the value
        value = juce::Array<juce::var>();
        if(length == -1)
        {
            // asn1 object of indefinite length, read until end tag
            for(;;)
            {
                V1::_checkBufferLength(bytes, remaining, 2);
                if( bytes.readShort() == 0 )
                {
                    remaining -= 2;
                    break;
                }
                start = bytes.getNumBytesRemaining();
                DBG( "creating value from push(_fromDer()) with indefinite length");
                value.append(_fromDer(bytes, remaining, depth + 1, options));
                remaining -= start - bytes.getNumBytesRemaining();
            }
        }
        else
        {
            // parsing asn1 object of definite length
            while(length > 0)
            {
                start = bytes.getNumBytesRemaining();
                DBG( "creating value from push(_fromDer()) with definite length");
                value.append(_fromDer(bytes, length, depth + 1, options));
                remaining -= start - bytes.getNumBytesRemaining();
                length -= start - bytes.getNumBytesRemaining();
            }
        }
    }
    
    // if a BIT STRING, save the contents including padding
    if( value.isVoid() && tagClass == ASN1::Class::UNIVERSAL &&
       type == ASN1::Type::BITSTRING )
    {
        //js ByteStringBuffer::bytes reads the data without changing the read position.
        //we can emulate this by getting the stream position, doing the read, and then setting the read position.
        //bitStringContents = bytes.bytes(length);
        auto pos = bytes.getPosition();
        juce::MemoryOutputStream mos(bitStringContents, false);
        mos.writeFromInputStream(bytes, length);
        bytes.setPosition(pos);
    }
    
    // determine if a non-constructed value should be decoded as a composed
    // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
    // can be used this way.
    if( value.isVoid() &&
       options["decodeBitStrings"].equalsWithSameType(true) &&
       tagClass == ASN1::Class::UNIVERSAL &&
       // FIXME: OCTET STRINGs not yet supported here
       // .. other parts of forge expect to decode OCTET STRINGs manually
       (type == ASN1::Type::BITSTRING /*|| type == ASN1::Type::OCTETSTRING*/) &&
       length > 1)
    {
        // save read position
        auto savedRead = bytes.getPosition();
        auto savedRemaining = remaining;
        juce::uint8 unused = 0;
        if(type == ASN1::Type::BITSTRING)
        {
            /* The first octet gives the number of bits by which the length of the
             bit string is less than the next multiple of eight (this is called
             the "number of unused bits").
             
             The second and following octets give the value of the bit string
             converted to an octet string. */
            V1::_checkBufferLength(bytes, remaining, 1);
            unused = bytes.readByte();
            remaining--;
        }
        // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
        if(unused == 0)
        {
//            try
            {
                // attempt to parse child asn1 object from the value
                // (stored in array to signal composed value)
                start = bytes.getNumBytesRemaining();
                auto subOptions = juce::NamedValueSet({
                    // enforce strict mode to avoid parsing ASN.1 from plain data
                    NV("strict", true),
                    NV("decodeBitStrings", true)
                });
                auto composed = _fromDer(bytes, remaining, depth + 1, subOptions);
                auto used = start - bytes.getNumBytesRemaining();
                remaining -= used;
                if(type == ASN1::Type::BITSTRING)
                {
                    used++;
                }
                
                // if the data all decoded and the class indicates UNIVERSAL or
                // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
                auto tc = static_cast<Class>(static_cast<int>(composed["tagClass"]));
                if(used == length &&
                   (tc == ASN1::Class::UNIVERSAL || tc == ASN1::Class::CONTEXT_SPECIFIC))
                {
//                    value = [composed];
                    DBG( "creating value = [composed];");
                    value = juce::Array<juce::var>{composed};
                }
            }
//            catch(ex)
//            {
//            }
        }
        if(value.isVoid())
        {
            // restore read position
            bytes.setPosition(savedRead);
            remaining = savedRemaining;
        }
    }
    
    if(value.isVoid())
    {
        // asn1 not constructed or composed, get raw value
        // TODO: do DER to OID conversion and vice-versa in .toDer?
        
        if(length == -1)
        {
            if(options["strict"].equalsWithSameType(true))
            {
                DBG( "Non-constructed ASN.1 object of indefinite length.");
                jassertfalse;
            }
            // be lenient and use remaining state bytes
            length = remaining;
        }
        
        if(type == ASN1::Type::BMPSTRING)
        {
            //value = ''; //an empty string
            DBG( "creating value from String.fromCharCode(bytes.getInt16());");
            auto tempStr = juce::String();
            for(; length > 0; length -= 2)
            {
                //value += String.fromCharCode(bytes.getInt16()); //append single character utf16 str to value
                V1::_checkBufferLength(bytes, remaining, 2);
                //js String.fromCharCode() returns a UTF16 string
                //Question: what is the equivalent juce version?
                auto shortBE = bytes.readShortBigEndian();
                auto utf16 = juce::CharPointer_UTF16( &shortBE );
                auto utf16Str = juce::String(utf16);
                tempStr += utf16Str;
                remaining -= 2;
            }
            
            value = tempStr;
        }
        else
        {
            juce::MemoryBlock mb;
            {
                juce::MemoryOutputStream mos(mb, false);
                mos.writeFromInputStream(bytes, length);
            }
//            value = bytes.getBytes(length);
            DBG( "creating value from bytes.getBytes(" << length << ")");
            value = mb;
            remaining -= length;
        }
    }
    
//    DBG( "_fromDer() final 'value' before asn1.create():" );
//    varPrinter(value);
    // add BIT STRING contents if available
    juce::NamedValueSet asn1Options;
    if(! bitStringContents.isEmpty() )
    {
        asn1Options.set("bitStringContents", bitStringContents);
    }
    
    // create and return asn1 object
    return create(tagClass, type, constructed, value, asn1Options);
#endif
}
} //end namespace V2
} //end namespace ASN1
} //end namespace Forge

void varPrinter(const juce::var& value, juce::String name)
{
    if( name.isNotEmpty() )
        name << ": ";

    if( value.isArray() )//if( forge.util.isArray(value) )
    {
        const auto& arr = *value.getArray();
        for( int i = 0; i < arr.size(); ++i )//for( var i = 0; i < value.length; ++i )
        {
            auto elem = arr[i]; //var elem = value[i];
            DBG( "elem[" << i << "]:" ); //console.log( `elem[${i}]:`);
            if( elem.isObject() )// if( typeof elem === "object")
            {
                auto obj = elem.getDynamicObject();
                const auto& props = obj->getProperties();
                for( auto prop : props )//for (const [key, v] of Object.entries(elem))
                {
                    const auto& key = prop.name.toString();
                    const auto& v = prop.value;
                    // if( key === "value" || key === "bitStringContents" )
                    {
                        // console.log( `${key}: ${forge.util.bytesToHex(v)}` );
                        varPrinter(v, key);
                    }
                    // else
                    {
                        // console.log(`${key}: ${v}`);
                    }
                }
            }
            else
            {
                DBG("not implemented yet");
            }
        }
    }
    else if( value.isBool() )//else if( typeof value === "bool" )
    {
//        console.log(name, (value === true ? "true" : "false") );
        DBG( name << (static_cast<bool>(value) == true ? "true" : "false" ) );
    }
    else if( value.isString() )//else if( typeof value === "string")
    {
//        console.log(name, forge.util.bytesToHex(value));
        auto str = value.toString();
        juce::MemoryBlock mb(str.getCharPointer(), str.length());
        DBG( name << juce::String::toHexString(mb.getData(), mb.getSize(), 0));
    }
    else if( value.isBinaryData() )
    {
        auto data = *value.getBinaryData();
        DBG( name << juce::String::toHexString(data.getData(), data.getSize(), 0));
    }
    else
    {
        DBG("'value' has unhandled type");
        DBG(name << value.toString());
    }
}

namespace Forge
{
namespace ASN1
{
namespace V2
{

juce::MemoryBlock integerToDer(juce::int32 x)
{
    auto rval = juce::MemoryBlock();
    auto mos = juce::MemoryOutputStream(rval, false);
    
    auto putBytes = [](juce::MemoryOutputStream& data, const juce::MemoryBlock& bytes)
    {
        juce::MemoryInputStream mis(bytes, false);
        data.writeFromInputStream(mis, mis.getNumBytesRemaining());
    };
    
    auto putInt = [&mos, &putBytes](int i, juce::uint32 n)
    {
        V1::_checkBitsParam(n);//_checkBitsParam(n);
        juce::MemoryBlock bytesBlock;//var bytes = '';
        {
        juce::MemoryOutputStream bytes(bytesBlock, false);
        do//do
        {//{
            n -= 8; //    n -= 8;
            bytes.writeByte((i >> n) & 0xFF); //    bytes += String.fromCharCode((i >> n) & 0xFF);
        }//}
        while(n > 0);//while(n > 0);
        }
        putBytes(mos, bytesBlock); //return this.putBytes(bytes);
    };
    
    auto putSignedInt = [&putInt](int i, juce::uint32 n)
    {
        /**
         * Puts a signed n-bit integer in this buffer in big-endian order. Two's
         * complement representation is used.
         *
         * @param i the n-bit integer.
         * @param n the number of bits in the integer (8, 16, 24, or 32).
         *
         * @return this buffer.
         */
          // putInt checks n
        
        jassert( n % 8 == 0 );
        jassert( n > 0 && n < 33 );
        if(i < 0)
        {
            i += 2 << (n - 1);
        }
        putInt(i, n); //return this.putInt(i, n);
    };
    
    if(x >= -0x80 && x < 0x80) {
//        mos.writeIntBigEndian(putSignedInt(x, 8)); // return rval.putSignedInt(x, 8);
        putSignedInt(x, 8);
    }
    else if(x >= -0x8000 && x < 0x8000) {
       putSignedInt(x, 16);//return rval.putSignedInt(x, 16);
    }
    else if(x >= -0x800000 && x < 0x800000) {
        putSignedInt(x, 24);//return rval.putSignedInt(x, 24);
    }
    else if(x >= -0x80000000 && x < 0x80000000) {
        putSignedInt(x, 32);//return rval.putSignedInt(x, 32);
    }
    else
    {
        jassertfalse;
    }
    mos.flush();
    DBG( "integerToDer(" << x << "): " << juce::String::toHexString(rval.getData(),
                                                                    rval.getSize(), 0));
    return rval;
}

juce::var create(Class tagClass,
                 Type type,
                 bool constructed,
                 juce::var value,
                 juce::NamedValueSet options)
{
    /* An asn1 object has a tagClass, a type, a constructed flag, and a
      value. The value's type depends on the constructed flag. If
      constructed, it will contain a list of other asn1 objects. If not,
      it will contain the ASN.1 value as an array of bytes formatted
      according to the ASN.1 data type. */

    // remove undefined values
//    if(forge.util.isArray(value))
    if( value.isArray() )
    {
        auto& arr = *value.getArray();
        juce::var tmp = juce::Array<juce::var>();
        for(int i = 0; i < arr.size(); ++i)
        {
            auto entry = arr[i];
            if(! entry.isVoid() && !entry.isUndefined())
            {
                tmp.append(entry);
            }
            else
            {
                jassertfalse;
            }
        }
        value = tmp;
    }
    
    juce::DynamicObject::Ptr obj = new juce::DynamicObject();
    obj->setProperty("tagClass", static_cast<int>(tagClass));
    obj->setProperty("type", static_cast<int>(type));
    obj->setProperty("constructed", constructed);
    obj->setProperty("composed", constructed || value.isArray());
    obj->setProperty("value", value);
    
    if(! options.isEmpty() && options.contains("bitStringContents") )
    {
        // TODO: copy byte buffer if it's a buffer not a string
        obj->setProperty("bitStringContents", options["bitStringContents"]);
        // TODO: add readonly flag to avoid this overhead
        // save copy to detect changes
//        DBG( juce::JSON::toString(obj.get()));
//        obj->setProperty("original", copy(juce::var(obj.get()), {}));
    }
    
    auto rval = juce::var(obj.get());
    return rval;
}

juce::var copy(const juce::var& obj, juce::NamedValueSet options)
{
    juce::var copy_;
    
    if( obj.isArray())
    {
        copy_ = juce::Array<juce::var>();
        auto& arr = *obj.getArray();
        for(int i = 0; i < arr.size(); ++i)
        {
            copy_.append(copy(arr[i], options));
        }
        return copy_;
    }
    
//    if(typeof obj === 'string')
    if( obj.isString() )
    {
        // TODO: copy byte buffer if it's a buffer not a string
        return obj;
    }
    
    jassert(obj.isObject() || obj.isBinaryData());
    if(! obj.isObject() && !obj.isBinaryData() )
    {
        return {};
    }
    
    DBG ("\n\ncopying object: " );
    DBG( juce::JSON::toString(obj));
    //TODO: compare the JSON output to what is shown in JS
    /*
     This copy step has some issues. Sometimes object is of type void. Sometimes object is type binary.
     the line:
        data->setProperty("value", copy(obj["value"], options));
     is the culprit here.
     
     I think there is a juce::JSON function taht lets me print out the way the juce::var object is currently structed.
     This would let me inspect how it is laid out, and see if it is lined up with the javascript version.
     */
    
    juce::DynamicObject::Ptr data = new juce::DynamicObject();
    
    data->setProperty("tagClass", obj["tagClass"]);
    data->setProperty("type", obj["type"]);
    data->setProperty("constructed", obj["constructed"]);
    data->setProperty("composed", obj["composed"]);
    data->setProperty("value", copy(obj["value"], options));
    
    if(!options.isEmpty() && options.getWithDefault("excludeBitStringContents",
                                                    true) //exclude by default
                                    .equalsWithSameType(false))
    {
        // TODO: copy byte buffer if it's a buffer not a string
        data->setProperty("bitStringContents", obj["bitStringContents"]);
    }
    
    copy_ = juce::var(data.get());
    return copy_;
};
} //end namespace V2
namespace V1
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
//    DBG( "OID: " << oid );
    auto values = juce::StringArray::fromTokens(oid, ".", "");
//    var bytes = forge.util.createBuffer();
    auto block = juce::MemoryBlock();
    auto bytes = juce::MemoryOutputStream(block, false);
    // first byte is 40 * value1 + value2
//    bytes.putByte(40 * parseInt(values[0], 10) + parseInt(values[1], 10));
    auto v0 = values[0].getIntValue();
    auto v1 = values[1].getIntValue();
    auto v = 40 * v0 + v1;
    bytes.writeByte(v);
//    bytes.writeShortBigEndian(40 + values[0].getIntValue() + values[1].getIntValue());
    // other bytes are each value in base 128 with 8th bit set except for
    // the last byte for each value
//    var last, valueBytes, value, b;
    bool last;
    std::vector<juce::uint8> valueBytes;
    juce::int64 value;
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
        
//        for( size_t j = 0; j < valueBytes.size(); ++j ) //for( var j = 0; j < valueBytes.length; ++j )
//        {
//            DBG( "valueBytes[" << i-2 << "][" << j << "]: " << valueBytes[j]);
//        }
        // add value bytes in reverse (needs to be in big endian)
//        for(var n = valueBytes.length - 1; n >= 0; --n)
        for (auto n = valueBytes.rbegin(); n != valueBytes.rend(); ++n)
        {
//            bytes.putByte(valueBytes[n]);
            auto byte = *n;
//            DBG( "writing byte: " << byte );
            bytes.writeByte(byte);
        }
    }

    bytes.flush();
//    DBG( "OID bytes: " << juce::String::toHexString(block.getData(), block.getSize(), 0));
    return block;
}
} //end namespace V1

namespace V2
{
juce::var toDer(const juce::var& obj)
{
    auto bytesBlock = juce::MemoryBlock();                                              //var bytes = forge.util.createBuffer();
    auto bytes = juce::MemoryOutputStream(bytesBlock, false);
                                                                                        //
    // build the first byte                                                             //// build the first byte
    juce::uint8 b1 = static_cast<juce::uint8>(static_cast<int>(obj["tagClass"])) |      //var b1 = obj.tagClass | obj.type;
                     static_cast<juce::uint8>(static_cast<int>(obj["type"]));
                                                                                        //
    // for storing the ASN.1 value                                                      //// for storing the ASN.1 value
    auto valueBlock = juce::MemoryBlock();                                              //var value = forge.util.createBuffer();
    auto value = juce::MemoryOutputStream(valueBlock, false);
                                                                                        //
    // use BIT STRING contents if available and data not changed                        //// use BIT STRING contents if available and data not changed
    bool useBitStringContents = false;                                                  //var useBitStringContents = false;
    if( obj.hasProperty("bitStringContents") )                                          //if('bitStringContents' in obj)
    {                                                                                   //{
        useBitStringContents = true;                                                    //    useBitStringContents = true;
        if(static_cast<bool>(obj["original"]))                                          //    if(obj.original)
        {                                                                               //    {
            jassertfalse; //not used in JS tests                                        //        useBitStringContents = asn1.equals(obj, obj.original);
        }                                                                               //    }
    }                                                                                   //}
                                                                                        //
    if(useBitStringContents)                                                            //if(useBitStringContents)
    {                                                                                   //{
        jassertfalse;                                                                   //    value.putBytes(obj.bitStringContents);
        auto mb = *obj["bitStringContents"].getBinaryData();
        juce::MemoryInputStream mis(mb, false);
        value.writeFromInputStream(mis, mb.getSize());
    }                                                                                   //}
    else if(obj["composed"].equalsWithSameType(true))                                   //else if(obj.composed)
    {                                                                                   //{
        // if composed, use each child asn1 object's DER bytes as value
        // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
        // from other asn1 objects
        if(obj["constructed"].equalsWithSameType(true))                                 //    if(obj.constructed)
        {                                                                               //    {
            b1 |= 0x20;                                                                 //        b1 |= 0x20;
        }                                                                               //    }
        else                                                                            //    else
        {                                                                               //    {
            // type is a bit string, add unused bits of 0x00                            //        // type is a bit string, add unused bits of 0x00
            value.writeByte(0x00);                                                      //        value.putByte(0x00);
        }                                                                               //    }
                                                                                        //
        // add all of the child DER bytes together                                      //    // add all of the child DER bytes together
        jassert(obj.hasProperty("value"));
        jassert(obj["value"].isArray());
        if( ! obj["value"].isArray() )
        {
            jassertfalse;
            return {};
        }
        
        const auto& arr = *obj["value"].getArray();
        for( int i = 0; i < arr.size(); ++i )                                           //    for(var i = 0; i < obj.value.length; ++i)
        {                                                                               //    {
            auto entry = arr[i];
            if(! entry.isUndefined() && !entry.isVoid())                                //        if(obj.value[i] !== undefined)
            {                                                                           //        {
                auto der = ASN1::V2::toDer(entry);                                      //            var der = asn1.toDer(obj.value[i]);
//                DBG( juce::JSON::toString(entry));
                if( !der.isBinaryData() )
                {
                    jassertfalse;
                }
                else
                {
                    auto memoryBlockToAdd = *der.getBinaryData();
//                    DBG( "ASN1::toDer(varToAdd:" );                                     //            console.log("ASN1::toDer(varToAdd:");
//                    DBG( juce::String::toHexString(memoryBlockToAdd.getData(),          //            console.log(der.toHex());
//                                                   memoryBlockToAdd.getSize(),
//                                                   0));
                    auto mis = juce::MemoryInputStream(memoryBlockToAdd, false);
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());        //            value.putBuffer(der);
                }
            }                                                                           //        }
        }                                                                               //    }
    }                                                                                   //}
    else                                                                                //else
    {                                                                                   //{
        // use asn1.value directly                                                      //    // use asn1.value directly
        if(obj["type"].equalsWithSameType(static_cast<int>(ASN1::Type::BMPSTRING)))     //    if(obj.type === asn1.Type.BMPSTRING)
        {                                                                               //    {
            jassertfalse; //this if() is not hit in the javascript for the PEM file we're working with
            jassert(obj["value"].isBinaryData());
            auto mb = *obj["value"].getBinaryData();
            /*
             javascript uses UTF16 characters, and stores them in Big Endian
             //TODO: cite this to confirm.
             */
            juce::MemoryInputStream mis(mb, false);
            while(! mis.isExhausted() )                                                 //        for(var i = 0; i < obj.value.length; ++i)
            {                                                                           //        {
                auto shValue = mis.readShortBigEndian();
                value.writeShortBigEndian( shValue );                                   //            value.putInt16(obj.value.charCodeAt(i));
            }                                                                           //        }
        }                                                                               //    }
        else                                                                            //    else
        {                                                                               //    {

            jassert(obj.hasProperty("type"));
            jassert(obj.hasProperty("value"));
            auto v = obj["value"];

            // ensure integer is minimally-encoded
            // TODO: should all leading bytes be stripped vs just one?
            // .. ex '00 00 01' => '01'?
            if( v.isBinaryData() )
            {
                auto mb = *v.getBinaryData();
                juce::MemoryInputStream mis(mb, false);
                
                if(obj["type"].equalsWithSameType(static_cast<int>(ASN1::Type::INTEGER)) && //        if(obj.type === asn1.Type.INTEGER &&
                   mb.getSize() > 1 &&                                                      //           obj.value.length > 1 &&
                   // leading 0x00 for positive integer                                     //           // leading 0x00 for positive integer
                   ((static_cast<juce::uint8>(mb[0]) == 0 &&                                //           ((obj.value.charCodeAt(0) === 0 &&
                     (static_cast<juce::uint8>(mb[1]) & 0x80) == 0) ||                      //             (obj.value.charCodeAt(1) & 0x80) === 0) ||
                    // leading 0xFF for negative integer                                    //            // leading 0xFF for negative integer
                     (static_cast<juce::uint8>(mb[0]) == 0xFF &&                            //            (obj.value.charCodeAt(0) === 0xFF &&
                      (static_cast<juce::uint8>(mb[1]) & 0x80) == 0x80)))                   //             (obj.value.charCodeAt(1) & 0x80) === 0x80)))
                {                                                                           //        {
                    mis.readByte(); //this advances the read position by 1
                    auto pos = mis.getPosition();
                    auto bytesToPut = juce::MemoryBlock();
                    auto mos = juce::MemoryOutputStream(bytesToPut, false);
                    mos.writeFromInputStream(mis, mis.getNumBytesRemaining());              //            var bytesToPut = obj.value.substr(1);
                    mos.flush();
                    jassertfalse;
                    DBG("bytesToPut: " << juce::String::toHexString(bytesToPut.getData(),   //            console.log(`bytesToPut: ${bytesToPut}`);
                                                                    bytesToPut.getSize(),
                                                                    0));
                    mis.setPosition(pos);
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());            //            value.putBytes(bytesToPut);
                }                                                                           //        }
                else                                                                        //        else
                {                                                                           //        {
                    auto pos = mis.getPosition();
                    auto bytesToPut = juce::MemoryBlock();
                    auto mos = juce::MemoryOutputStream(bytesToPut, false);
                    mos.writeFromInputStream(mis, mis.getNumBytesRemaining());
                    mos.flush();
//                    DBG( "obj.value: " << juce::String::toHexString(bytesToPut.getData(),
//                                                                    bytesToPut.getSize(),
//                                                                    0));
                    mis.setPosition(pos);
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());            //            value.putBytes(obj.value);
                }                                                                           //        }
            }
            else if(! v.isVoid() )
            {
                //do nothing for now.
                jassertfalse;
            }
        }                                                                               //    }
    }                                                                                   //}
                                                                                        //
    // add tag byte                                                                     //// add tag byte
    bytes.writeByte(b1);                                                                //bytes.putByte(b1);
                                                                                        //
    value.flush(); //this trims the size of valueBlock to the length of data actually written to valueBlock.  see documentation tooltip
    // use "short form" encoding                                                        //// use "short form" encoding
    if(valueBlock.getSize() <= 127)                                                     //if(value.length() <= 127)
    {                                                                                   //{
        // one byte describes the length                                                //    // one byte describes the length
        // bit 8 = 0 and bits 7-1 = length                                              //    // bit 8 = 0 and bits 7-1 = length
        bytes.writeByte(valueBlock.getSize() & 0x7F);                                   //    bytes.putByte(value.length() & 0x7F);
    }                                                                                   //}
    else                                                                                //else
    {                                                                                   //{
        // use "long form" encoding
        // 2 to 127 bytes describe the length
        // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
        // other bytes: length in base 256, big-endian
        auto len = valueBlock.getSize();                                                //    var len = value.length();
        /*
         NOTE: Juce doesn't support memoryBlocks with a size that requires more than 8 bytes to represent.
         The JS code is strange
         It appears to create a string from the length bytes in big-endian
         */
        juce::MemoryBlock lenBytesBlock;
        juce::MemoryOutputStream lenBytes(lenBytesBlock, false);                        //    var lenBytes = '';
        do                                                                              //    do
        {                                                                               //    {
            lenBytes.writeByte(len & 0xFF);                                             //        lenBytes += String.fromCharCode(len & 0xFF);
            len = len >> 8;                                                             //        len = len >>> 8;
        }                                                                               //    }
        while(len > 0);                                                                 //    while(len > 0);
        lenBytes.flush();
                                                                                        //
        // set first byte to # bytes used to store the length and turn on
        // bit 8 to indicate long-form length is used
        bytes.writeByte(lenBytesBlock.getSize() | 0x80);                                //    bytes.putByte(lenBytes.length | 0x80);
                                                                                        //
        // concatenate length bytes in reverse since they were generated
        // little endian and we need big endian
        for( int i = lenBytesBlock.getSize() - 1; i >= 0; --i )                         //    for(var i = lenBytes.length - 1; i >= 0; --i)
        {                                                                               //    {
            bytes.writeByte(lenBytesBlock[i]);                                          //        bytes.putByte(lenBytes.charCodeAt(i));
        }                                                                               //    }
    }                                                                                   //}
                                                                                        //
    // concatenate value bytes                                                          //// concatenate value bytes
    juce::MemoryInputStream mis(valueBlock, false);
    bytes.writeFromInputStream(mis, mis.getNumBytesRemaining());                        //bytes.putBuffer(value);
    bytes.flush();
//    DBG("toDer() result: " << juce::String::toHexString(bytesBlock.getData(),           //console.log(`toDer() result: ${bytes.toHex()}`);
//                                                        bytesBlock.getSize(),
//                                                        0) );
    return bytesBlock;                                                                  //return bytes;
#if false
//asn1.toDer = function(obj)
//{
//    var bytes = forge.util.createBuffer();
    auto bytesBlock = juce::MemoryBlock();
    auto bytes = juce::MemoryOutputStream(bytesBlock, false);
    
    // build the first byte
//    var b1 = obj.tagClass | obj.type;
    char b1 = static_cast<char>(static_cast<int>(obj["tagClass"])) | static_cast<char>(static_cast<int>(obj["type"]));
    
    // for storing the ASN.1 value
//    var value = forge.util.createBuffer();
    auto valueBlock = juce::MemoryBlock();
    auto value = juce::MemoryOutputStream(valueBlock, false);
    
    // use BIT STRING contents if available and data not changed
//    var useBitStringContents = false;
    bool useBitStringContents = false;
//    if('bitStringContents' in obj)
    if( obj.hasProperty("bitStringContents") )
    {
        useBitStringContents = true;
        //TODO: I'm not even storing 'original' in obj
        jassertfalse;
//        if(obj.original)
//        {
//            useBitStringContents = asn1.equals(obj, obj.original);
//        }
    }
    
    if(useBitStringContents)
    {
//        value.putBytes(obj.bitStringContents);
        jassertfalse;
        auto mb = *obj["bitStringContents"].getBinaryData();
        juce::MemoryInputStream mis(mb, false);
        value.writeFromInputStream(mis, mb.getSize());
    }
//    else if(obj.composed)
    else if( obj.hasProperty("composed") && obj["composed"].equalsWithSameType(true))
    {
        // if composed, use each child asn1 object's DER bytes as value
        // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
        // from other asn1 objects
        if( obj.hasProperty("constructed") &&
           obj["constructed"].equalsWithSameType(true) ) //if(obj.constructed) {
        {
            b1 |= 0x20;
        }
        else
        {
            // type is a bit string, add unused bits of 0x00
            value.writeByte(0x00); //value.putByte(0x00);
        }
#if false
        // add all of the child DER bytes together
        for(var i = 0; i < obj.value.length; ++i) {
          if(obj.value[i] !== undefined)
          {
            var der = asn1.toDer(obj.value[i]);
            //Figure out how to print out the DER as base64 string and compare with C++ base64 strings
            console.log("ASN1::toDer(varToAdd:");
            console.log(der.toHex());
            value.putBuffer(der);
          }
        }
#endif
        jassert(obj.hasProperty("value"));
        jassert(obj["value"].isArray());
        if( obj.hasProperty("value") && obj["value"].isArray() )
        {
            const auto& arr = *obj["value"].getArray();
            for( int i = 0; i < arr.size(); ++i )
            {
                if(! arr[i].isUndefined() )
                {
                    auto der = ASN1::V2::toDer(arr[i]);
                    jassert(der.isBinaryData());
                    auto memoryBlockToAdd = *der.getBinaryData();
                    DBG( "ASN1::toDer(varToAdd:" );
                    DBG( juce::String::toHexString(memoryBlockToAdd.getData(), memoryBlockToAdd.getSize(), 0));
                    auto mis = juce::MemoryInputStream(memoryBlockToAdd, false);
                    value.writeFromInputStream(mis,
                                               mis.getNumBytesRemaining());
                }
            }
        }
    }
    else
    {
        // use asn1.value directly
//        if(obj.type === asn1.Type.BMPSTRING)
        if( obj.hasProperty("type") && obj["type"].equalsWithSameType(static_cast<int>(ASN1::Type::BMPSTRING)))
        {
            jassertfalse; //this if() is not hit in the javascript for the PEM file we're working with
#if false
            for(var i = 0; i < obj.value.length; ++i) {
              value.putInt16(obj.value.charCodeAt(i));
            }
#endif
            jassert(obj["value"].isBinaryData());
            auto mb = *obj["value"].getBinaryData();
            
            /*
             javascript uses UTF16 characters, and stores them in Big Endian
             //TODO: cite this to confirm.
             */
            juce::MemoryInputStream mis(mb, false);
            for( size_t i = 0; i < mis.getTotalLength() / 2; ++i )
            {
                auto shValue = mis.readShortBigEndian();
                value.writeShortBigEndian( shValue );
            }
        }
        else
        {
#if false
            // ensure integer is minimally-encoded
            // TODO: should all leading bytes be stripped vs just one?
            // .. ex '00 00 01' => '01'?
            if(obj.type === asn1.Type.INTEGER &&
              obj.value.length > 1 &&
              // leading 0x00 for positive integer
              ((obj.value.charCodeAt(0) === 0 &&
              (obj.value.charCodeAt(1) & 0x80) === 0) ||
              // leading 0xFF for negative integer
              (obj.value.charCodeAt(0) === 0xFF &&
              (obj.value.charCodeAt(1) & 0x80) === 0x80))) {
              value.putBytes(obj.value.substr(1));
            } else {
              value.putBytes(obj.value);
            }
#endif
            jassert(obj.hasProperty("value"));
            
            if( obj["value"].isBinaryData() )
            {
                const auto bd = *obj["value"].getBinaryData();
                
                if(obj["type"].equalsWithSameType(static_cast<int>( ASN1::Type::INTEGER)) &&    //if(obj.type === asn1.Type.INTEGER &&
                   bd.getSize() > 1 &&                                                          //  obj.value.length > 1 &&
                   // leading 0x00 for positive integer                                         //  // leading 0x00 for positive integer
                   ((static_cast<juce::uint8>(bd[0]) == 0 &&                                    //  ((obj.value.charCodeAt(0) === 0 &&
                     (static_cast<juce::uint8>(bd[1]) & 0x80) == 0) ||                          //  (obj.value.charCodeAt(1) & 0x80) === 0) ||
                    // leading 0xFF for negative integer                                        //  // leading 0xFF for negative integer
                    (static_cast<juce::uint8>(bd[0]) == 0xFF &&                                 //  (obj.value.charCodeAt(0) === 0xFF &&
                     (static_cast<juce::uint8>(bd[1]) & 0x80) == 0x80)))                        //  (obj.value.charCodeAt(1) & 0x80) === 0x80)))
                {
                    jassert(obj["value"].isBinaryData());
                    
                    if(! obj["value"].isBinaryData() )
                    {
                        jassertfalse;
                        return {};
                    }
                    
                    //                value.putBytes(obj.value.substr(1));
                    juce::MemoryInputStream mis(bd, false);
                    mis.readByte(); //this advances the read position by 1
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());
                }
                else
                {
                    //                value.putBytes(obj.value);
                    auto mb = *obj["value"].getBinaryData();
                    juce::MemoryInputStream mis(bd, false);
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());
                }
            }
            else if(! obj["value"].isVoid() )
            {
                jassertfalse;
            }
        }
    }
    
    // add tag byte
//    bytes.putByte(b1);
    bytes.writeByte(b1);
    
    value.flush(); //this trims the size of valueBlock to the length of data actually written to valueBlock.  see documentation tooltip
    
    // use "short form" encoding
    if( valueBlock.getSize() <= 127 ) //if(value.length() <= 127)
    {
        // one byte describes the length
        // bit 8 = 0 and bits 7-1 = length
        bytes.writeByte(valueBlock.getSize() & 0x7F); //bytes.putByte(value.length() & 0x7F);
    }
    else
    {
        // use "long form" encoding
        // 2 to 127 bytes describe the length
        // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
        // other bytes: length in base 256, big-endian
#if false
        var len = value.length();
        var lenBytes = '';
        do {
          lenBytes += String.fromCharCode(len & 0xFF);
          len = len >>> 8;
        } while(len > 0);

        // set first byte to # bytes used to store the length and turn on
        // bit 8 to indicate long-form length is used
        bytes.putByte(lenBytes.length | 0x80);

        // concatenate length bytes in reverse since they were generated
        // little endian and we need big endian
        for(var i = lenBytes.length - 1; i >= 0; --i) {
          bytes.putByte(lenBytes.charCodeAt(i));
        }
#endif
        auto len = valueBlock.getSize(); //var len = value.length();
        /*
         NOTE: Juce doesn't support memoryBlocks with a size that requires more than 8 bytes to represent.
         The JS code above is strange
         It appears to create a string from the length bytes in big-endian
         */
        juce::MemoryBlock lenBytesBlock;
        juce::MemoryOutputStream lenBytes(lenBytesBlock, false);
//        juce::String lenBytes;
        do
        {
            lenBytes.writeByte(len & 0xFF); //lenBytes += String.fromCharCode(len & 0xFF);
            /*
             The static String.fromCharCode() method returns a string created from the specified sequence of UTF-16 code units.
             */
//            char utf8uffer = len & 0xFF;
//            lenBytes += *(juce::String::fromUTF8(&utf8uffer).toUTF16());
            len = len >> 8; //len = len >>> 8;
        }
        while(len > 0);
        lenBytes.flush();

        // set first byte to # bytes used to store the length and turn on
        // bit 8 to indicate long-form length is used

        bytes.writeByte(lenBytesBlock.getSize() | 0x80); //bytes.putByte(lenBytes.length | 0x80);

        // concatenate length bytes in reverse since they were generated
        // little endian and we need big endian
//        for( int i = lenBytes.length() - 1; i >= 0; --i) //for(var i = lenBytes.length - 1; i >= 0; --i)
        {
            /*
             String.prototype.charCodeAt()
             The charCodeAt() method returns an integer between 0 and 65535 representing the UTF-16 code unit at the given index.
             putByte writes 1 byte, but UTF16 requires 2 bytes.
             this is strange.
             */
//            juce::uint16 charCode = *(lenBytes.substring(i, 1).toUTF16());
//            bytes.putByte(lenBytes.charCodeAt(i));
//            bytes.writeByte(charCode);
        }
        for( int i = lenBytesBlock.getSize() - 1; i >= 0; --i )
        {
            bytes.writeByte( lenBytesBlock[i]);
        }
    }
    
    // concatenate value bytes
//    bytes.putBuffer(value);
//    return bytes;
    juce::MemoryInputStream mis(valueBlock, false);
    bytes.writeFromInputStream(mis, mis.getNumBytesRemaining());
    bytes.flush();
    DBG("toDer() result: " << juce::String::toHexString(bytesBlock.getData(), bytesBlock.getSize(), 0) );
    return bytesBlock;
#endif
}

bool validate(const juce::var& obj,
              const juce::var& v,
              juce::var& capture,
              juce::StringArray& errors)
{
    bool rval = false;
    
    auto DBGHelper = [](const auto& obj, const auto& v, const auto& p)
    {
        if( obj[p].isBool() && v[p].isBool() )
        {
            DBG(p << " " << (static_cast<bool>(obj[p]) == true ? "true" : "false" ) << " " << (static_cast<bool>(v[p]) == true ? "true" : "false") << " equalsWithSameType: " << static_cast<int>(obj[p].equalsWithSameType(v[p])));
        }
        else
        {
            DBG(p << " " << obj[p].toString() << " " << v[p].toString() << " equalsWithSameType: " << static_cast<int>(obj[p].equalsWithSameType(v[p])));
        }
        
    };
    DBGHelper(obj, v, "tagClass");
    DBGHelper(obj, v, "type");
    // ensure tag class and type are the same if specified
    if( (obj["tagClass"].equalsWithSameType(v["tagClass"]) || v["tagClass"].isVoid() ) &&
       (obj["type"].equalsWithSameType(v["type"]) || v["type"].isVoid()) )
    {
        // ensure constructed flag is the same if specified
        DBGHelper(obj, v, "constructed");
        if( obj["constructed"].equalsWithSameType(v["constructed"]) || v["constructed"].isVoid() )
        {
            rval = true;
            
            // handle sub values
            if( v.hasProperty("value") && v["value"].isArray() )
            {
                int j = 0;
                auto& v_value_arr = *v["value"].getArray();
                for(int i = 0; rval && i < v_value_arr.size(); ++i)
                {
                    rval = static_cast<bool>(v_value_arr[i]["optional"]) || false;
                    
                    if(! obj["value"].isArray() )
                    {
                        jassertfalse; //obj.value should exist
                        return false;
                    }
                    
                    auto& obj_value_arr = *obj["value"].getArray();
                    if(obj_value_arr[j])
                    {
                        rval = validate(obj_value_arr[j], v_value_arr[i], capture, errors);
                        if(rval)
                        {
                            ++j;
                        }
                        else if(v_value_arr[i]["optional"].equalsWithSameType(true))
                        {
                            rval = true;
                        }
                    }
                    if(!rval)
                    {
                        juce::String error;
                        error << "[" << v["name"].toString() << "] ";
                        error << "Tag class \"" << v["tagClass"].toString() << "\", type ";
                        error << v["type"].toString() << "\" expected value length \"";
                        error << v["value"].getArray()->size() << "\", got \"";
                        error << obj["value"].getArray()->size() << "\"";
                        errors.add(error);
                    }
                }
            }
            
            if(rval && capture.isObject())
            {
                if(v.hasProperty("capture"))
                {
                    DBG( "capturing: " << v["capture"].toString());
                    capture.getDynamicObject()->setProperty(v["capture"].toString(), obj["value"]);
                }
                if( v.hasProperty("captureAsn1"))
                {
                    capture.getDynamicObject()->setProperty(v["captureAsn1"].toString(), obj);
                }
                if( v.hasProperty("captureBitStringContents") && obj.hasProperty("bitStringContents"))
                {
                    capture.getDynamicObject()->setProperty(v["captureBitStringContents"].toString(), obj["bitStringContents"]);
                }
                if( v.hasProperty("captureBitStringValue") && obj.hasProperty("bitStringContents"))
                {
                    auto& mb = *obj["bitStringContents"].getBinaryData();
                    if(mb.getSize() < 2)
                    {
                        capture.getDynamicObject()->setProperty(v["captureBitStringValue"].toString(), "");
                    }
                    else
                    {
                        // FIXME: support unused bits with data shifting
//                        var unused = obj.bitStringContents.charCodeAt(0)
                        auto unused = mb.getBitRange(0, 8);
                        if(unused != 0)
                        {
//                            throw new Error(
//                                            'captureBitStringValue only supported for zero unused bits');
                            DBG( "captureBitStringValue only supported for zero unused bits");
                            jassertfalse;
                            return false;
                        }
                        //capture every byte except the first one.
                        //capture[v.captureBitStringValue] = obj.bitStringContents.slice(1);
                        juce::MemoryBlock sliced;
                        {
                            juce::MemoryOutputStream mos(sliced, false);
                            
                            juce::MemoryInputStream mis(mb, false);
                            mis.readByte();
                            mos.writeFromInputStream(mis, mis.getNumBytesRemaining());
                        }
                        capture.getDynamicObject()->setProperty(v["captureBitStringValue"].toString(), sliced);
                        
                    }
                }
            }
        }
        else //if(errors)
        {
            juce::String error;
            error << "[" << v["name"].toString() << "] ";
            error << "Expected constructed \"" << static_cast<int>(static_cast<bool>(v["constructed"])) << "\", got \"";
            error << static_cast<int>(static_cast<bool>(obj["constructed"])) << "\"";
            errors.add(error);
//            errors.push(
//                        '[' + v.name + '] ' +
//                        'Expected constructed "' + v.constructed + '", got "' +
//                        obj.constructed + '"');
        }
    }
    else //if(errors)
    {
        if(! obj["tagClass"].equalsWithSameType(v["tagClass"] ))
        {
            juce::String error;
            error << "[" << v["name"].toString() << "] ";
            error << "Expected tag class \"" << static_cast<int>(v["tagClass"]) << "\", got \"";
            error << static_cast<int>(obj["tagClass"]) << "\"";
            errors.add(error);
//            errors.push(
//                        '[' + v.name + '] ' +
//                        'Expected tag class "' + v.tagClass + '", got "' +
//                        obj.tagClass + '"');
        }
//        if(obj.type !== v.type)
        if( ! obj["type"].equalsWithSameType(v["type"]) )
        {
            juce::String error;
            error << "[" << v["name"].toString() << "] ";
            error << "Expected type \"" << static_cast<int>(v["type"]) << "\", got \"" << static_cast<int>(obj["type"]) << "\"";
            errors.add(error);
//            errors.push(
//                        '[' + v.name + '] ' +
//                        'Expected type "' + v.type + '", got "' + obj.type + '"');
        }
    }
    return rval;
};
} //end namespace V2
} //end namespace ASN1
} //end namespace Forge
