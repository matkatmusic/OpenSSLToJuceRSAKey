/*
  ==============================================================================

    BaseN.h
    Created: 26 Jun 2022 11:01:02am
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>
/*
 a port of https://github.com/digitalbazaar/forge/blob/main/lib/baseN.js
 */

/**
 * Base-N/Base-X encoding/decoding functions.
 *
 * Original implementation from base-x:
 * https://github.com/cryptocoinjs/base-x
 *
 * Which is MIT licensed:
 *
 * The MIT License (MIT)
 *
 * Copyright base-x contributors (c) 2016
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
//var api = {};
//module.exports = api;

// baseN alphabet indexes
//var _reverseAlphabets = {};

namespace Forge
{
struct API
{
    

/**
 * BaseN-encodes a Uint8Array using the given alphabet.
 *
 * @param input the Uint8Array to encode.
 * @param maxline the maximum number of encoded characters per line to use,
 *          defaults to none.
 *
 * @return the baseN-encoded output string.
 */
//api.encode = function(input, alphabet, maxline) {
    juce::String encode(const std::vector<juce::uint8>& input, juce::String alphabet, size_t maxline = 0)
    {
//        if(typeof alphabet !== 'string') {
//            throw new TypeError('"alphabet" must be a string.');
//        }
        jassert(alphabet.isNotEmpty());
        if( alphabet.isEmpty() )
        {
            DBG( "alphabet must not be empty" );
            return {};
        }
//        if(maxline !== undefined && typeof maxline !== 'number') {
//            throw new TypeError('"maxline" must be a number.');
//        }
        
//        var output = '';
        juce::String output;
        
//        if(!(input instanceof Uint8Array))
//        {
//            // assume forge byte buffer
//            output = _encodeWithByteBuffer(input, alphabet);
//        }
//        else
        {
//            var i = 0;
            size_t i = 0;
//            var base = alphabet.length;
            auto base = alphabet.length();
//            var first = alphabet.charAt(0);
            auto first = alphabet.substring(0, 1);
//            var digits = [0];
            std::vector<juce::uint8> digits = {0};
//            for(i = 0; i < input.length; ++i)
            for( i = 0; i < input.size(); ++i )
            {
//                for(var j = 0, carry = input[i]; j < digits.length; ++j)
                juce::uint64 carry = input[i];
                for( size_t j = 0; j < digits.size(); ++j )
                {
                    carry += digits[j] << 8;
                    digits[j] = carry % base;
                    carry = (carry / base) | 0;
                }
                
                while(carry > 0)
                {
//                    digits.push(carry % base);
                    digits.push_back(carry % base);
                    carry = (carry / base) | 0;
                }
            }
            
            // deal with leading zeros
            for(i = 0; input[i] == 0 && i < input.size() - 1; ++i)
            {
                output += first;
            }
            // convert digits to a string
            for(i = digits.size() - 1; i >= 0; --i)
            {
                output += alphabet[digits[i]];
            }
        }
        
//        if(maxline)
        if( maxline != 0 )
        {
//            var regex = new RegExp('.{1,' + maxline + '}', 'g');
//            output = output.match(regex).join('\r\n');
            //insert a '\r\n' every maxline characters
            decltype(output) temp;
            for( int i = 0; i < output.length(); ++i )
            {
                temp << output.substring(i, i+1);
                if( i % maxline == 0 )
                {
                    temp << '\r';
                    temp << '\n';
                }
            }
            
            output = temp;
        }
        
        return output;
    }

/**
 * Decodes a baseN-encoded (using the given alphabet) string to a
 * Uint8Array.
 *
 * @param input the baseN-encoded input string.
 *
 * @return the Uint8Array.
 */
//api.decode = function(input, alphabet) {
    std::vector<juce::uint8> decode(juce::String input, juce::String alphabet)
    {
//        if(typeof input !== 'string') {
//            throw new TypeError('"input" must be a string.');
//        }
        jassert(input.isNotEmpty());
        if( input.isEmpty() )
        {
            DBG( "input must not be empty" );
            return {};
        }
//        if(typeof alphabet !== 'string') {
//            throw new TypeError('"alphabet" must be a string.');
//        }
        jassert(alphabet.isNotEmpty());
        if( alphabet.isEmpty() )
        {
            DBG( "alphabet must not be empty" );
            return {};
        }
        
//        var table = _reverseAlphabets[alphabet];
        std::vector<juce::uint8> table;
        table.resize(alphabet.length(), 0);
//        if(!table) {
            // compute reverse alphabet
//            table = _reverseAlphabets[alphabet] = [];
//        for(var i = 0; i < alphabet.length; ++i) {
        for( int i = 0; i < alphabet.length(); ++i )
        {
//            table[alphabet.charCodeAt(i)] = i;
            table[ alphabet[i] ] = i;
        }
//        }
        
        // remove whitespace characters
//        input = input.replace(/\s/g, '');
        input = input.trim();
        
//        var base = alphabet.length;
        auto base = alphabet.length();
//        var first = alphabet.charAt(0);
        auto first = alphabet[0];
//        var bytes = [0];
        std::vector<juce::uint8> bytes = {0};
//        for(var i = 0; i < input.length; i++)
        for( int i = 0; i < input.length(); ++i )
        {
//            var value = table[input.charCodeAt(i)];
//            if(value === undefined)
//            {
//                return;
//            }
            auto idx = input[i];
            if(! juce::isPositiveAndBelow(idx, table.size()))
            {
                return {};
            }
            auto value = table[idx];
            
            juce::uint64 carry = value;
//            for(var j = 0, carry = value; j < bytes.length; ++j)
            for( size_t j = 0; j < bytes.size(); ++j )
            {
                carry += bytes[j] * base;
                bytes[j] = carry & 0xff;
                carry >>= 8;
            }
            
            while(carry > 0)
            {
//                bytes.push(carry & 0xff);
                bytes.push_back(carry & 0xff);
                carry >>= 8;
            }
        }
        
        // deal with leading zeros
//        for(var k = 0; input[k] === first && k < input.length - 1; ++k)
        for( int k = 0; input[k] == first && k < input.length() - 1; ++k)
        {
//            bytes.push(0);
            bytes.push_back(0);
        }
        
//        if(typeof Buffer !== 'undefined')
//        {
//            return Buffer.from(bytes.reverse());
//        }
        auto rev = bytes;
        std::reverse(rev.begin(), rev.end());
//        return new Uint8Array(bytes.reverse());
        return rev;
    }

//    function _encodeWithByteBuffer(input, alphabet)
    juce::String _encodeWithByteBuffer(std::vector<juce::uint8> input, juce::String alphabet)
    {
//        var i = 0;
        size_t i = 0;
//        var base = alphabet.length;
        auto base = alphabet.length();
//        var first = alphabet.charAt(0);
        auto first = alphabet[0];
//        var digits = [0];
        std::vector<juce::uint8> digits = {0};
        for(i = 0; i < input.size(); ++i)
        {
//            for(var j = 0, carry = input.at(i); j < digits.length; ++j)
            juce::uint64 carry = input[i];
            for( size_t j = 0; j < digits.size(); ++j )
            {
                carry += digits[j] << 8;
                digits[j] = carry % base;
                carry = (carry / base) | 0;
            }
            
            while(carry > 0)
            {
//                digits.push(carry % base);
                digits.push_back(carry % base);
                carry = (carry / base) | 0;
            }
        }
        
//        var output = '';
        juce::String output;
        
        // deal with leading zeros
//        for(i = 0; input.at(i) === 0 && i < input.length() - 1; ++i)
        for( int i = 0; input[i] == 0 && i < input.size() - 1; ++i )
        {
//            output += first;
            output << first;
        }
        // convert digits to a string
//        for(i = digits.length - 1; i >= 0; --i)
        for( size_t i = digits.size() - 1; i >=0; --i )
        {
            jassert( juce::isPositiveAndBelow(digits[i], alphabet.length()));
//            output += alphabet[digits[i]];
            output << alphabet[ digits[i] ];
        }
        
        return output;
    }
}; //end struct API
} //end namespace Forge
