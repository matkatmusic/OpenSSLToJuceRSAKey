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
namespace V2
{
juce::Array<juce::NamedValueSet> decode(const juce::String& pemString)
{
    juce::Array<juce::NamedValueSet> rval;
    
    auto str = pemString;
#if false
    DBG(pemString);
    DBG("");
#endif
    
    // split string into PEM messages (be lenient w/EOF on BEGIN line)
    auto rMessage = juce::String(R"REGEX(\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----)REGEX");
    auto rHeader = juce::String(R"REGEX(([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+))REGEX");
    auto rCRLF = juce::String(R"REGEX(\r?\n)REGEX");
    std::regex characters("\\s*-----BEGIN ([A-Z0-9- ]+)-----\\r?\\n?([\\x21-\\x7e\\s]+?(?:\\r?\\n\\r?\\n))?([:A-Za-z0-9+\\/=\\s]+?)-----END \\1-----");
    auto stdString = str.toStdString();
    auto characters_begin = std::sregex_iterator(stdString.begin(), stdString.end(), characters);
    auto characters_end = std::sregex_iterator();
    
    std::smatch match;
    std::regex_search(stdString, match, characters);
#if false
    if(! match.empty() )
    {
        DBG( "found: " << match.size() << " matches" );
        for( size_t n = 0; n < match.size(); ++n )
        {
            DBG( "[" << n << "]:" << match[n] );
        }
    }
    else
    {
        DBG( "no matches!" );
    }
#endif
    
    while(true)
    {
        auto regexMatch = Forge::RegexFunctions::searchAndGetMatches(rMessage, str);
#if false
        DBG( "matches: ");
        int i = 0;
        for( auto m : regexMatch )
        {
            DBG(i << ": " << m );
            ++i;
        }
#endif
        
        if( regexMatch.isEmpty() )
        {
            break;
        }
        
        // accept "NEW CERTIFICATE REQUEST" as "CERTIFICATE REQUEST"
        // https://datatracker.ietf.org/doc/html/rfc7468#section-7
        if( regexMatch.size() < 2 )
        {
            jassertfalse;
            break;
        }
        
        auto type = regexMatch[1];
        if(type == "NEW CERTIFICATE REQUEST")
        {
            type = "CERTIFICATE REQUEST";
        }
        
#if false
        DBG( regexMatch[3].length() );
        DBG( regexMatch[3] );
#endif
        //remove all \r\n from msg.body
        auto base64Text = regexMatch[3];
        base64Text = base64Text.removeCharacters("\r\n");
#if false
        DBG( base64Text.length() );
#endif
        using NV = juce::NamedValueSet::NamedValue;
        juce::MemoryBlock bodyBlock;
        {
            juce::MemoryOutputStream mos(bodyBlock, false);
            bool successfulConversion = juce::Base64::convertFromBase64(mos, base64Text);
            if(! successfulConversion )
            {
                jassertfalse;
            }
        }
#if false
        DBG( bodyBlock.getSize() );
#endif
        juce::NamedValueSet msg
        {
            NV("type", type),
            NV("procType", {}), //empty juce::var
            NV("contentDomain", {}),
            NV("dekInfo", {}),
            NV("headers", juce::Array<juce::var>()),
            NV("body", bodyBlock)
        };
//        var msg = {
//            type: type,
//            procType: null,
//            contentDomain: null,
//            dekInfo: null,
//            headers: [],
//            body: forge.util.decode64(match[3])
//        };
        rval.add(msg);
        
#if false
        // no headers
        if(match[2].length() == 0 )
        {
            continue;
        }
        
        // parse headers
        auto lines = juce::StringArray::fromLines(match[2]);
        auto li = 0;
        while( /* match */ && li < lines.length() )
        {
            // get line, trim any rhs whitespace
            auto line = lines[li].trim();
            
            // RFC2822 unfold any following folded lines
            for( auto nextLine = li + 1; nextLine < lines.length(); ++nextLine )
            {
                auto next = lines[nextLine];
                if(!/\s/.test(next[0]))
                {
                    break;
                }
                line += next;
                li = nextLine;
            }
            
            // parse header
            match = line.match(rHeader);
            if(match)
            {
                var header = {name: match[1], values: []};
                var values = match[2].split(',');
                for(var vi = 0; vi < values.length; ++vi)
                {
                    header.values.push(ltrim(values[vi]));
                }
                
                // Proc-Type must be the first header
                if(!msg.procType)
                {
                    if(header.name !== 'Proc-Type')
                    {
                        throw new Error('Invalid PEM formatted message. The first ' +
                                        'encapsulated header must be "Proc-Type".');
                    }
                    else if(header.values.length !== 2)
                    {
                        throw new Error('Invalid PEM formatted message. The "Proc-Type" ' +
                                        'header must have two subfields.');
                    }
                    msg.procType = {version: values[0], type: values[1]};
                }
                else if(!msg.contentDomain && header.name === 'Content-Domain')
                {
                    // special-case Content-Domain
                    msg.contentDomain = values[0] || '';
                }
                else if(!msg.dekInfo && header.name === 'DEK-Info')
                {
                    // special-case DEK-Info
                    if(header.values.length === 0)
                    {
                        throw new Error('Invalid PEM formatted message. The "DEK-Info" ' +
                                        'header must have at least one subfield.');
                    }
                    msg.dekInfo = {algorithm: values[0], parameters: values[1] || null};
                }
                else
                {
                    msg.headers.push(header);
                }
            }
            
            ++li;
        }
#endif
        if(msg.getVarPointer("procType")->isString() &&
           msg.getVarPointer("procType")->toString() == "ENCRYPTED" &&
           msg.getVarPointer("dekInfo")->isVoid() )
        {
            DBG("Invalid PEM formatted message. The \"DEK-Info\" header must be present if \"Proc-Type\" is \"ENCRYPTED\".");
            jassertfalse;
            return {};
        }
        /*
         from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/exec
         JavaScript RegExp objects are stateful when they have the global or sticky flags set (e.g. /foo/g or /foo/y). They store a lastIndex from the previous match. Using this internally, exec() can be used to iterate over multiple matches in a string of text (with capture groups), as opposed to getting just the matching strings with String.prototype.match().
         
         for my purposes, I can replace the 0th entry in the returned match with ''
         */
        str = str.replace(regexMatch[0], "");
    }
    
    if( rval.size() == 0 )
    {
        DBG( "Invalid PEM formatted message." );
        jassertfalse;
        return {};
    }
    
    return rval;
}
} //end namespace V2
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
