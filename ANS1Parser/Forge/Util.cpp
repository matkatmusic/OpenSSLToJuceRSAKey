/*
  ==============================================================================

    Util.cpp
    Created: 26 Jun 2022 11:00:48am
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "Util.h"

/*
 need:
 [x] util.createBuffer -> toHex()
 [x] util.bytesToHex
 [x] util.decodeUtf8 -> decodeURIComponent() -> escape()
 [x] util.ByteBuffer -> ByteStringBuffer
 [x] util.ByteStringBuffer.prototype.toHex
 */
namespace Forge
{
namespace Util
{
juce::String encode64(juce::MemoryBlock input, int maxLine)    //util.encode64 = function(input, maxline)
{   //{
    //    // TODO: deprecate: "Deprecated. Use util.binary.base64.encode instead."
    juce::String line;//    var line = '';
    juce::String output;//    var output = '';
    unsigned char chr1, chr2, chr3; //    var chr1, chr2, chr3;
    int i = 0;//    var i = 0;
    const auto& _base64 = getBase64();
    while( i < input.getSize() )//    while(i < input.length)
    {//    {
        chr1 = input[i++];//        chr1 = input.charCodeAt(i++);
        chr2 = input[i++];//        chr2 = input.charCodeAt(i++);
        chr3 = input[i++];//        chr3 = input.charCodeAt(i++);
    //
    //        // encode 4 character group
        line += _base64[(chr1 >> 2)];//        line += _base64.charAt(chr1 >> 2);
        line += _base64[((chr1 & 3) << 4) | (chr2 >> 4)];//        line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
        if( std::isnan(chr2))//        if(isNaN(chr2))
        {//        {
            line += "==";//            line += '==';
        }//        }
        else//        else
        {//        {
            line += _base64[(((chr2 & 15) << 2) | (chr3 >> 6))];//            line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
            line += std::isnan(chr3) ? "=" : juce::String(_base64[(chr3 & 63)]);//            line += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
        }//        }
    //
        if( maxLine > 0 && line.length() > maxLine)//        if(maxline && line.length > maxline)
        {//        {
            output += line.substring(0, maxLine) + '\r' + '\n'; //            output += line.substr(0, maxline) + '\r\n';
            line = line.substring(maxLine); //            line = line.substr(maxline);
        }//        }
    }//    }
    output += line; //    output += line;
    return output;//    return output;
}   //};
} //end namespace Util
} //end namespace Forge
