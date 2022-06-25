/*
  ==============================================================================

    PEMHelpers.h
    Created: 25 Jun 2022 12:32:39pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>

struct PEMHelpers
{
    static juce::MemoryBlock convertPEMStringToPEMMemoryBlock(juce::String pemString)
    {
        juce::MemoryBlock mb;
        {
            juce::MemoryOutputStream mos(mb, false);
            auto ok = juce::Base64::convertFromBase64(mos, pemString);
            jassert(ok);
            juce::ignoreUnused(ok);
        }
        
        return mb;
    }
    
    static juce::String convertPEMMemoryBlockToPEMString(juce::MemoryBlock byteArray)
    {
        juce::MemoryBlock resultBlock;
        juce::MemoryOutputStream resultMOS(resultBlock, false);
        juce::Base64::convertToBase64(resultMOS, byteArray.getData(), byteArray.getSize());
        
        auto result = resultBlock.toString();
        
        return result;
    }
    
    static juce::String convertPEMPublicKeyToString(juce::String pubKey)
    {
        jassert( pubKey.contains("-----BEGIN"));
        jassert( pubKey.contains("-----END"));
        
        if( !pubKey.contains("MII") )
        {
            DBG( "your key has less than 2048 bits!  You should increase the key size" );
        }
        
        auto keyDataArr = juce::StringArray::fromLines(pubKey);
        auto lastLineIndex = [&keyDataArr]()
        {
            int i = 0;
            for( auto str : keyDataArr )
            {
                if( str.contains("-----END") )
                    return i;
                
                ++i;
            }
            
            return -1;

        }();
        jassert(lastLineIndex != -1);
        keyDataArr.remove(lastLineIndex);
        keyDataArr.remove(0);
        keyDataArr.removeEmptyStrings();
        
        auto pemData = keyDataArr.joinIntoString("");
        
        DBG( "pemData: " );
        DBG( pemData );
        
        return pemData;
    }
    
    static juce::String toHex(juce::uint8 value)
    {
        static const char* hexChars = "0123456789abcdef";
        
        juce::String str;
        auto v = value;
        
        while( v > 0 )
        {
            auto idx = v & 0xf;
            str = hexChars[ idx ] + str;
            v >>= 4;
        }
        
        //insert a zero at the front.
        if( value < 16 )
        {
            str = "0" + str;
        }
        
        return str;
    }
    
    static juce::uint8 fromHex(juce::String str)
    {
        jassert( str.length() == 2 );
        
        juce::uint8 value = 0;
        static juce::String hexChars { "0123456789abcdef" };
        
        for( int i = 0; i < str.length(); ++i )
        {
            value += hexChars.indexOf( str.substring(i, i+1) );
            if( i == 0 )
                value <<= 4;
        }
        
        return value;
    }
    
    
};
