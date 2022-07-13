/*
  ==============================================================================

    Pem.h
    Created: 9 Jul 2022 7:29:28pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>
#include <regex>
/*
 a port of https://github.com/digitalbazaar/forge/blob/main/lib/pem.js
 */
#if false
/**
 * Javascript implementation of basic PEM (Privacy Enhanced Mail) algorithms.
 *
 * See: RFC 1421.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2013-2014 Digital Bazaar, Inc.
 *
 * A Forge PEM object has the following fields:
 *
 * type: identifies the type of message (eg: "RSA PRIVATE KEY").
 *
 * procType: identifies the type of processing performed on the message,
 *   it has two subfields: version and type, eg: 4,ENCRYPTED.
 *
 * contentDomain: identifies the type of content in the message, typically
 *   only uses the value: "RFC822".
 *
 * dekInfo: identifies the message encryption algorithm and mode and includes
 *   any parameters for the algorithm, it has two subfields: algorithm and
 *   parameters, eg: DES-CBC,F8143EDE5960C597.
 *
 * headers: contains all other PEM encapsulated headers -- where order is
 *   significant (for pairing data like recipient ID + key info).
 *
 * body: the binary-encoded body.
 */
var forge = require('./forge');
require('./util');

// shortcut for pem API
var pem = module.exports = forge.pem = forge.pem || {};

/**
 * Encodes (serializes) the given PEM object.
 *
 * @param msg the PEM message object to encode.
 * @param options the options to use:
 *          maxline the maximum characters per line for the body, (default: 64).
 *
 * @return the PEM-formatted string.
 */
pem.encode = function(msg, options) {
  options = options || {};
  var rval = '-----BEGIN ' + msg.type + '-----\r\n';

  // encode special headers
  var header;
  if(msg.procType) {
    header = {
      name: 'Proc-Type',
      values: [String(msg.procType.version), msg.procType.type]
    };
    rval += foldHeader(header);
  }
  if(msg.contentDomain) {
    header = {name: 'Content-Domain', values: [msg.contentDomain]};
    rval += foldHeader(header);
  }
  if(msg.dekInfo) {
    header = {name: 'DEK-Info', values: [msg.dekInfo.algorithm]};
    if(msg.dekInfo.parameters) {
      header.values.push(msg.dekInfo.parameters);
    }
    rval += foldHeader(header);
  }

  if(msg.headers) {
    // encode all other headers
    for(var i = 0; i < msg.headers.length; ++i) {
      rval += foldHeader(msg.headers[i]);
    }
  }

  // terminate header
  if(msg.procType) {
    rval += '\r\n';
  }

  // add body
  rval += forge.util.encode64(msg.body, options.maxline || 64) + '\r\n';

  rval += '-----END ' + msg.type + '-----\r\n';
  return rval;
};
#endif
/**
 * Decodes (deserializes) all PEM messages found in the given string.
 *
 * @param str the PEM-formatted string to decode.
 *
 * @return the PEM message objects in an array.
 */
namespace Forge
{
/** A Helper class that encapsulates the regex operations */
class RegexFunctions
{
public:
    
    static juce::Array<juce::StringArray> findSubstringsThatMatchWildcard(const juce::String &regexWildCard, const juce::String &stringToTest)
    {
        juce::Array<juce::StringArray> matches;
        juce::String remainingText = stringToTest;
        juce::StringArray m = getFirstMatch(regexWildCard, remainingText);

        while (m.size() != 0 && m[0].length() != 0)
        {
            remainingText = remainingText.fromFirstOccurrenceOf(m[0], false, false);
            matches.add(m);
            m = getFirstMatch(regexWildCard, remainingText);
        }

        return matches;
    }

    /** Searches a string and returns a StringArray with all matches.
    *    You can specify and index of a capture group (if not, the entire match will be used). */
    static juce::StringArray search(const juce::String& wildcard, const juce::String &stringToTest, int indexInMatch=0)
    {
        try
        {
            juce::StringArray searchResults;

            std::basic_regex includeRegex(wildcard.toStdString());
            std::string xAsStd = stringToTest.toStdString();
            std::sregex_iterator it(xAsStd.begin(), xAsStd.end(), includeRegex);
            std::sregex_iterator it_end;

            while (it != it_end)
            {
                std::smatch result = *it;

                juce::StringArray matches;
                for (auto x : result)
                {
                    matches.add(juce::String(x));
                }

                if (indexInMatch < matches.size())
                    searchResults.add(matches[indexInMatch]);

                ++it;
            }

            return searchResults;
        }
        catch (std::regex_error e)
        {
            DBG(e.what());
            return juce::StringArray();
        }
    }

    /** Returns the first match of the given wildcard in the test string. The first entry will be the whole match, followed by capture groups. */
    static juce::StringArray getFirstMatch(const juce::String &wildcard, const juce::String &stringToTest)
    {
        try
        {
            std::regex reg(wildcard.toStdString());
            std::string s(stringToTest.toStdString());
            std::smatch match;
            

            if (std::regex_search(s, match, reg))
            {
                juce::StringArray sa;

                for (auto x:match)
                {
                    sa.add(juce::String(x));
                }
                
                return sa;
            }
            
            return juce::StringArray();
        }
        catch (std::regex_error e)
        {
            jassertfalse;

            DBG(e.what());
            return juce::StringArray();
        }
    }
    
    /** Checks if the given string matches the regex wildcard. */
    static bool matchesWildcard(const juce::String &wildcard, const juce::String &stringToTest)
    {
        try
        {
            std::regex reg(wildcard.toStdString());
            
            return std::regex_search(stringToTest.toStdString(), reg);
        }
        catch (std::regex_error e)
        {
            DBG(e.what());
            
            return false;
        }
    }

    static juce::StringArray searchAndGetMatches(const juce::String& regex, const juce::String& strToSearch)
    {
        std::regex characters(regex.toStdString());
        auto stdString = strToSearch.toStdString();
        auto characters_begin = std::sregex_iterator(stdString.begin(),
                                                     stdString.end(),
                                                     characters);
        auto characters_end = std::sregex_iterator();
        
        std::smatch match;
        std::regex_search(stdString, match, characters);
        
        juce::StringArray matches;
        if(! match.empty() )
        {
            for( size_t n = 0; n < match.size(); ++n )
            {
                matches.add( juce::String(match[n]) );
            }
        }
        
        return matches;
    }
};

namespace Pem
{

struct Msg
{
    juce::String type;
    void* procType = nullptr;
    void* contentDomain = nullptr;
    void* dekInfo = nullptr;
    juce::StringArray headers;
    juce::MemoryBlock body;
};

template<typename ArrayType, typename StringType>
ArrayType decode(const StringType& pemString)
{
//pem.decode = function(str) {
    ArrayType rval;
    //  var rval = [];
    StringType str = pemString;
    DBG(pemString);
    DBG("");
    // split string into PEM messages (be lenient w/EOF on BEGIN line)
//    var rMessage = /\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----/g;
    auto rMessage = juce::String(R"REGEX(\s*-----BEGIN ([A-Z0-9- ]+)-----\r?\n?([\x21-\x7e\s]+?(?:\r?\n\r?\n))?([:A-Za-z0-9+\/=\s]+?)-----END \1-----)REGEX");
//    auto rMessage = juce::String("\\s*-----BEGIN ([A-Z0-9- ]+)-----\\r?\\n?([\\x21-\\x7e\\s]+?(?:\\r?\\n\\r?\\n))?([:A-Za-z0-9+\\/=\\s]+?)-----END \\1-----");
//    var rHeader = /([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+)/;
    auto rHeader = juce::String(R"REGEX(([\x21-\x7e]+):\s*([\x21-\x7e\s^:]+))REGEX");
//    var rCRLF = /\r?\n/;
    auto rCRLF = juce::String(R"REGEX(\r?\n)REGEX");
//    var match;
    
    /*
     JS uses regex to parse the incoming string into 'full', 'token', empty, 'data'
     This post shows how to do this with std::regex:
     https://forum.juce.com/t/does-juce-team-have-any-plan-to-support-regular-expression-for-juce-string/21677/3
     See the helper functions above.
     */
    
//    std::regex characters("\s*-----BEGIN ([A-Z0-9- ]+)-----(?:\r?\n?)?(?:[A-Za-z0-9+\/=\s]+?)?");
    std::regex characters("\\s*-----BEGIN ([A-Z0-9- ]+)-----\\r?\\n?([\\x21-\\x7e\\s]+?(?:\\r?\\n\\r?\\n))?([:A-Za-z0-9+\\/=\\s]+?)-----END \\1-----");
    auto stdString = str.toStdString();
    auto characters_begin = std::sregex_iterator(stdString.begin(), stdString.end(), characters);
    auto characters_end = std::sregex_iterator();
    
    std::smatch match;
    std::regex_search(stdString, match, characters);
    
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
//    DBG( "found: " << std::distance(characters_begin, characters_end) << " characters" );
//    for (std::sregex_iterator i = characters_begin; i != characters_end; ++i)
    {
//        std::smatch match = *i;
//        std::string match_str = match.str();
//        DBG( juce::String(match_str) );
    }
    
    while(true)
    {
//        match = rMessage.exec(str);
//        auto match = Forge::RegexFunctions::search(rMessage, str);
        auto match = Forge::RegexFunctions::searchAndGetMatches(rMessage, str);
        DBG( "matches: ");
        int i = 0;
        for( auto m : match )
        {
            DBG(i << ": " << m );
            ++i;
        }
//        if(!match)
        if( match.isEmpty() )
        {
            break;
        }
        
        // accept "NEW CERTIFICATE REQUEST" as "CERTIFICATE REQUEST"
        // https://datatracker.ietf.org/doc/html/rfc7468#section-7
//        var type = match[1];
        if( match.size() < 2 )
        {
            jassertfalse;
            break;
        }
        
        auto type = match[1];
//        if(type === 'NEW CERTIFICATE REQUEST')
        if( type == "NEW CERTIFICATE REQUEST")
        {
//            type = 'CERTIFICATE REQUEST';
            type = "CERTIFICATE REQUEST";
        }
        
        
        
//        var msg =
//        {
//        type: type,
//        procType: null,
//        contentDomain: null,
//        dekInfo: null,
//        headers: [],
//        body: forge.util.decode64(match[3])
//        };
        
        if( match.size() < 4 )
        {
            jassertfalse;
            break;
        }
        Msg msg;
        msg.type = type;
        
        juce::MemoryOutputStream mos(msg.body, false);
//        msg.body = juce::Base64::convertFromBase64(mos, match[3]);
        bool successfulConversion = juce::Base64::convertFromBase64(mos, match[3].trim());
        if(! successfulConversion )
        {
            jassertfalse;
        }
//        rval.push(msg);
        rval.add(msg);
        
        //skip headers for now.
#if false
        // no headers
//        if(!match[2])
        if( match[2].length() == 0 )
        {
            continue;
        }
        
        // parse headers
//        var lines = match[2].split(rCRLF);
        auto lines = juce::StringArray::fromLines(match[2]);
//        var li = 0;
        auto li = 0;
//        while(match && li < lines.length)
        while( /* match */ && li < lines.length() )
        {
            // get line, trim any rhs whitespace
//            var line = lines[li].replace(/\s+$/, '');
            auto line = lines[li].trim();
            
            // RFC2822 unfold any following folded lines
//            for(var nextline = li + 1; nextline < lines.length; ++nl)
            for( auto nextLine = li + 1; nextLine < lines.length(); ++nextLine )
            {
//                var next = lines[nextline];
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
                    } else if(header.values.length !== 2)
                    {
                        throw new Error('Invalid PEM formatted message. The "Proc-Type" ' +
                                        'header must have two subfields.');
                    }
                    msg.procType = {version: values[0], type: values[1]};
                }
                else if(!msg.contentDomain && header.name === 'Content-Domain') {
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
        
        if(msg.procType === 'ENCRYPTED' && !msg.dekInfo)
        {
            throw new Error('Invalid PEM formatted message. The "DEK-Info" ' +
                            'header must be present if "Proc-Type" is "ENCRYPTED".');
        }
#endif
        /*
         from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/exec
         JavaScript RegExp objects are stateful when they have the global or sticky flags set (e.g. /foo/g or /foo/y). They store a lastIndex from the previous match. Using this internally, exec() can be used to iterate over multiple matches in a string of text (with capture groups), as opposed to getting just the matching strings with String.prototype.match().
         
         for my purposes, I can replace the 0th entry in the returned match with ''
         */
        str = str.replace(match[0], "");
    }
    
//    if(rval.length === 0)
    if( rval.size() == 0 )
    {
//        throw new Error('Invalid PEM formatted message.');
        DBG( "Invalid PEM formatted message." );
        jassertfalse;
        return {};
    }
    
    return rval;
};

} //end namespace Pem
} //end namspace Forge

#if false
function foldHeader(header) {
  var rval = header.name + ': ';

  // ensure values with CRLF are folded
  var values = [];
  var insertSpace = function(match, $1) {
    return ' ' + $1;
  };
  for(var i = 0; i < header.values.length; ++i) {
    values.push(header.values[i].replace(/^(\S+\r\n)/, insertSpace));
  }
  rval += values.join(',') + '\r\n';

  // do folding
  var length = 0;
  var candidate = -1;
  for(var i = 0; i < rval.length; ++i, ++length) {
    if(length > 65 && candidate !== -1) {
      var insert = rval[candidate];
      if(insert === ',') {
        ++candidate;
        rval = rval.substr(0, candidate) + '\r\n ' + rval.substr(candidate);
      } else {
        rval = rval.substr(0, candidate) +
          '\r\n' + insert + rval.substr(candidate + 1);
      }
      length = (i - candidate - 1);
      candidate = -1;
      ++i;
    } else if(rval[i] === ' ' || rval[i] === '\t' || rval[i] === ',') {
      candidate = i;
    }
  }

  return rval;
}

function ltrim(str) {
  return str.replace(/^\s+/, '');
}
#endif
