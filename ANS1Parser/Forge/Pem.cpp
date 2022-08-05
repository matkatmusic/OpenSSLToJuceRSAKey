/*
  ==============================================================================

    Pem.cpp
    Created: 9 Jul 2022 7:29:28pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "Pem.h"

namespace Forge
{
namespace PEM
{

juce::String encode(const juce::NamedValueSet& msg, const juce::NamedValueSet& options)
{
//    options = options || {};
//    var rval = '-----BEGIN ' + msg.type + '-----\r\n';
    juce::String rval;
    rval << "-----BEGIN ";
    jassert(msg.contains("type"));
    rval << (*msg.getVarPointer("type")).toString();
    rval << "-----\r\n";
    // encode special headers
//    var header;
    juce::String header;
//    if(msg.procType)
    if( msg.contains("procType"))
    {
        jassertfalse;
#if false
        header = {
        name: 'Proc-Type',
        values: [String(msg.procType.version), msg.procType.type]
        };
        rval += foldHeader(header);
#endif
    }
//    if(msg.contentDomain)
    if( msg.contains("contentDomain") )
    {
        jassertfalse;
#if false
        header = {name: 'Content-Domain', values: [msg.contentDomain]};
        rval += foldHeader(header);
#endif
    }
//    if(msg.dekInfo)
    if( msg.contains("dekInfo") )
    {
        jassertfalse;
#if false
        header = {name: 'DEK-Info', values: [msg.dekInfo.algorithm]};
        if(msg.dekInfo.parameters)
        {
            header.values.push(msg.dekInfo.parameters);
        }
        rval += foldHeader(header);
#endif
    }
    
//    if(msg.headers)
    if( msg.contains("headers") )
    {
        jassertfalse;
#if false
        // encode all other headers
        for(var i = 0; i < msg.headers.length; ++i)
        {
            rval += foldHeader(msg.headers[i]);
        }
#endif
    }
    
    // terminate header
//    if(msg.procType)
    if( msg.contains("procType") )
    {
        jassertfalse;
#if false
        rval += '\r\n';
#endif
    }
    
    // add body
//    rval += forge.util.encode64(msg.body, options.maxline || 64) + '\r\n';
    
    jassert( msg.contains("body") );
    jassert( msg.getVarPointer("body")->isBinaryData() );
    auto* memBlockBody = msg.getVarPointer("body")->getBinaryData();
    auto& mb = *memBlockBody;
    auto b64 = juce::Base64::toBase64(mb.getData(), mb.getSize());
    
    auto maxLineLength = [&msg]() -> int
    {
        if( msg.contains("maxLine") && msg.getVarPointer("maxLine")->isInt() )
            return msg.getVarPointer("maxLine")->operator int();
        
        return 64;
    }();
    
    int i = 0;
    while( i < b64.length() )
    {
        rval << b64.substring(i, maxLineLength );
        i += maxLineLength;
        if( i < b64.length() )
            rval << "\r\n";
    }
    
    rval << "\r\n";
//    rval += '-----END ' + msg.type + '-----\r\n';
    rval << "-----END ";
    rval << (*msg.getVarPointer("type")).toString();
    rval << "-----\r\n";
    
    return rval;
};
} //end namespace PEM
} //end namespace Forge
