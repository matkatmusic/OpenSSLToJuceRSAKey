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
            value = mb;
            remaining -= length;
        }
    }
    
//    console.log( "_fromDer() final 'value' before asn1.create():  " );
    DBG( "_fromDer() final 'value' before asn1.create():" );
//    if( forge.util.isArray(value) )
    varPrinter(value);
    // add BIT STRING contents if available
    juce::NamedValueSet asn1Options;
    if(! bitStringContents.isEmpty() )
    {
        asn1Options.set("bitStringContents", bitStringContents);
    }
    
    // create and return asn1 object
    return create(tagClass, type, constructed, value, asn1Options);
}
} //end namespace V2
} //end namespace ASN1
} //end namespace Forge

void varPrinter(const juce::var& value, juce::String name)
{
    if( name.isNotEmpty() )
        name << ": ";
    
    if( value.isArray() )
    {
        auto& arr = *value.getArray();
        //      for( var i = 0; i < value.length; ++i )
        for( int i = 0; i < arr.size(); ++i )
        {
            //            var elem = value[i];
            auto& elem = arr.getReference(i);
            //            console.log( `elem[${i}]:`);
            DBG( "elem[" << i << "]:");
            //            if( typeof elem === "object")
            if( elem.isObject() )
            {
                //                for (const [key, v] of Object.entries(elem))
                auto& obj = *elem.getDynamicObject();
                auto props = obj.getProperties();
                for( auto prop : props )
                {
                    const auto& key = prop.name.toString();
                    const auto& v = prop.value;
                    if( key == "value" || key == "bitStringContents" )
                    {
                        if( v.isBinaryData() )
                        {
                            auto data = *v.getBinaryData();
                            //                        console.log( `${key}: ${forge.util.bytesToHex(v)}` );
                            DBG( key << ": " << juce::String::toHexString(data.getData(), data.getSize(), 0));
                        }
                        else
                        {
                            varPrinter(v, key);
                        }
                    }
                    else
                    {
                        varPrinter(v, key);
                    }
                }
            }
            else
            {
                //                console.log("not implemented yet");
                DBG( "not implemented yet" );
                jassertfalse; //TODO: figure out type of 'value'
            }
        }
    }
    else if( value.isBinaryData() )
    {
        //        console.log(forge.util.bytesToHex(value));
        jassert(value.isBinaryData());
        auto data = *value.getBinaryData();
        DBG( name << juce::String::toHexString(data.getData(), data.getSize(), 0) );
    }
    else if( value.isBool() )
    {
        DBG( name << (static_cast<bool>(value) == true ? "true" : "false") );
    }
    else
    {
        DBG( name << value.toString() );
    }
}

namespace Forge
{
namespace ASN1
{
namespace V2
{
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
            if(! arr[i].isVoid())
            {
                tmp.append(arr[i]);
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
} //end namespace V1

namespace V2
{
juce::var toDer(const juce::var& obj)
{
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
//        if(obj.constructed)
        if( obj.hasProperty("constructed") && obj["constructed"].equalsWithSameType(true))
        {
            b1 |= 0x20;
        }
        else
        {
            // type is a bit string, add unused bits of 0x00
//            value.putByte(0x00);
            value.writeByte(0x00);
        }
        
        // add all of the child DER bytes together
        if( obj.hasProperty("value") && obj["value"].isArray() )
        {
            auto& arr = *obj["value"].getArray();
            for( int i = 0; i < arr.size(); ++i )
            {
                if( ! arr[i].isUndefined() )
                {
                    auto varToAdd = ASN1::V2::toDer(arr[i]);
                    jassert(varToAdd.isBinaryData());
                    auto memoryBlockToAdd = *varToAdd.getBinaryData();
                    DBG( "" );
                    DBG( "ASN1::toDer(varToAdd: " );
                    DBG( juce::String::toHexString(memoryBlockToAdd.getData(), memoryBlockToAdd.getSize(), 0));
//                    DBG( juce::Base64::toBase64(memoryBlockToAdd.getData(), memoryBlockToAdd.getSize()));
                    auto mis = juce::MemoryInputStream(memoryBlockToAdd, false);
                    value.writeFromInputStream(mis,
                                               mis.getNumBytesRemaining());
                }
            }
        }
#if false
        for(var i = 0; i < obj.value.length; ++i)
        {
            if(obj.value[i] !== undefined)
            {
                value.putBuffer(asn1.toDer(obj.value[i]));
            }
        }
#endif
    }
    else
    {
        // use asn1.value directly
//        if(obj.type === asn1.Type.BMPSTRING)
        if( obj.hasProperty("type") && obj["type"].equalsWithSameType(static_cast<int>(ASN1::Type::BMPSTRING)))
        {
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
#if false
            for(var i = 0; i < obj.value.length; ++i)
            {
                value.putInt16(obj.value.charCodeAt(i));
            }
#endif
        }
        else
        {
            // ensure integer is minimally-encoded
            // TODO: should all leading bytes be stripped vs just one?
            // .. ex '00 00 01' => '01'?
//            if(obj.type === asn1.Type.INTEGER &&
            if( obj["type"].equalsWithSameType(static_cast<int>(ASN1::Type::INTEGER)) &&
//               obj.value.length > 1 &&
               obj["value"].getBinaryData()->getSize() > 1 &&
               // leading 0x00 for positive integer
//               ((obj.value.charCodeAt(0) === 0 &&
               ((obj["value"].getBinaryData()->operator[](0) == 0 &&
//                 (obj.value.charCodeAt(1) & 0x80) === 0) ||
                 (obj["value"].getBinaryData()->operator[](1) & 0x80) == 0) ||
                // leading 0xFF for negative integer
//                (obj.value.charCodeAt(0) === 0xFF &&
                (static_cast<unsigned char>(obj["value"].getBinaryData()->operator[](0)) == 0xFF &&
//                 (obj.value.charCodeAt(1) & 0x80) === 0x80)))
                 (obj["value"].getBinaryData()->operator[](1) & 0x80) == 0x80)))
            {
//                value.putBytes(obj.value.substr(1));
                jassert(obj.hasProperty("value"));
                jassert(obj["value"].isBinaryData());
                auto mb = *obj["value"].getBinaryData();
                juce::MemoryInputStream mis(mb, false);
                mis.readByte();
                value.writeFromInputStream(mis, mis.getNumBytesRemaining());
            }
            else
            {
//                value.putBytes(obj.value);
                jassert(obj.hasProperty("value"));
                if( obj["value"].isBinaryData() )
                {
                    auto mb = *obj["value"].getBinaryData();
                    juce::MemoryInputStream mis(mb, false);
                    value.writeFromInputStream(mis, mis.getNumBytesRemaining());
                }
                else if( obj["value"].isString() )
                {
                    auto str = obj["value"].toString();
                    value.writeString(str);
                }
                else
                {
                    //what type is obj["value"]
                    jassertfalse;
                }
            }
        }
    }
    
    // add tag byte
//    bytes.putByte(b1);
    bytes.writeByte(b1);
    
    // use "short form" encoding
    value.flush(); //this trims the size of valueBlock to the length of data actually written to valueBlock.  see documentation tooltip
//    if(value.length() <= 127)
    if( valueBlock.getSize() <= 127 )
    {
        // one byte describes the length
        // bit 8 = 0 and bits 7-1 = length
//        bytes.putByte(value.length() & 0x7F);
        bytes.writeByte(valueBlock.getSize() & 0x7F);
    }
    else
    {
        // use "long form" encoding
        // 2 to 127 bytes describe the length
        // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
        // other bytes: length in base 256, big-endian
//        var len = value.length();
        auto len = valueBlock.getSize();
        /*
         NOTE: Juce doesn't support memoryBlocks with a size that requires more than 8 bytes to represent.
         The JS code below is strange
         It appears to create a string from the length bytes in big-endian
         */
//        var lenBytes = '';
        juce::String lenBytes;
        do
        {
//            lenBytes += String.fromCharCode(len & 0xFF);
            /*
             The static String.fromCharCode() method returns a string created from the specified sequence of UTF-16 code units.
             */
//            lenBytes += juce::String(len & 0xFF);
            char utf8uffer = len & 0xFF;
            lenBytes += *(juce::String::fromUTF8(&utf8uffer).toUTF16());
//            len = len >>> 8;
            len = len >> 8;
        }
        while(len > 0);
        
        // set first byte to # bytes used to store the length and turn on
        // bit 8 to indicate long-form length is used
//        bytes.putByte(lenBytes.length | 0x80);
        bytes.writeByte(lenBytes.length() | 0x80);
        
        // concatenate length bytes in reverse since they were generated
        // little endian and we need big endian
//        for(var i = lenBytes.length - 1; i >= 0; --i)
        for( int i = lenBytes.length() - 1; i >= 0; --i)
        {
            /*
             String.prototype.charCodeAt()
             The charCodeAt() method returns an integer between 0 and 65535 representing the UTF-16 code unit at the given index.
             putByte writes 1 byte, but UTF16 requires 2 bytes.
             this is strange.
             */
            juce::uint16 charCode = *(lenBytes.substring(i, 1).toUTF16());
//            bytes.putByte(lenBytes.charCodeAt(i));
            bytes.writeByte(charCode);
        }
    }
    
    // concatenate value bytes
//    bytes.putBuffer(value);
//    return bytes;
    juce::MemoryInputStream mis(valueBlock, false);
    bytes.writeFromInputStream(mis, mis.getNumBytesRemaining());
    bytes.flush();
    return bytesBlock;
}

bool validate(const juce::var& obj,
              const juce::var& v,
              juce::var& capture,
              juce::StringArray& errors)
{
    bool rval = false;
    
    auto DBGHelper = [](const auto& obj, const auto& v, const auto& p)
    {
        DBG(p << " " << obj[p].toString() << " " << v[p].toString() << " equalsWithSameType: " << static_cast<int>(obj[p].equalsWithSameType(v[p])));
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
