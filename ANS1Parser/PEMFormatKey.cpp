/*
  ==============================================================================

    PEMFormatKey.cpp
    Created: 25 Jun 2022 12:15:45pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "PEMFormatKey.h"
#include "PEMHelpers.h"

void PEMFormatKey::loadFromPEMFormattedString(juce::String key)
{
    /*
     extract the base64 data from the key
     */
    auto pemString = PEMHelpers::convertPEMPublicKeyToString(key);
    
    if( ! pemString.contains("MII") && !pemString.contains("MIG") )
    {
        jassertfalse;
        //it's not a PEM key.  abort!
        DBG( "invalid key!" );
        return;
    }

    /*
     convert it into a MemoryBlock
     */
    auto pemData = PEMHelpers::convertPEMStringToPEMMemoryBlock(pemString);
    
    /*
     convert the MemoryBlock into an ASN1-formatted object with nested hierarchy
     */
    juce::MemoryInputStream mis(pemData, false);
    
    auto asn1 = ASN1Decoder::decode(mis);
    
    /*
     navigate the ASN1 hierarchy and find the modulus and exponent.
    read the exponent and modulus
     */
    
    if( key.contains("-----BEGIN PUBLIC KEY-----") )
    {
        loadPublicKey(asn1);
    }
    else if( key.contains("-----BEGIN PRIVATE KEY-----"))
    {
        loadPrivateKey(asn1);
    }
    else
    {
        DBG( "unsupported key format:" );
        DBG( juce::StringArray::fromLines(key).getReference(0) );
        jassertfalse;
    }
}

bool PEMFormatKey::loadPublicKey(ASN1::Ptr asn1)
{
    jassert( asn1->sub.size() == 2 );
    if( asn1->sub.size() != 2 )
    {
        jassertfalse;
        //it's not a PEM key.  abort!
        DBG( "invalid key!" );
        return false;
    }
    auto bitString = asn1->sub.back();
    jassert(bitString->sub.size() == 1);
    if( bitString->sub.size() != 1 )
    {
        jassertfalse;
        //it's not a PEM key.  abort!
        DBG( "invalid key!" );
        return false;
    }
    auto sequence = bitString->sub.front();
    jassert(sequence->sub.size() == 2);
    if( sequence->sub.size() != 2 )
    {
        jassertfalse;
        //it's not a PEM key.  abort!
        DBG( "invalid key!" );
        return false;
    }
    
    auto modulusBigInteger = convertANS1NodeToBigInteger(sequence->sub.front());
    auto exponentBigInteger = convertANS1NodeToBigInteger(sequence->sub.back());
    
    /*
     now that you're finished parsing, assign the exponent and modulus appropriately.
     */
    part1 = exponentBigInteger;
    part2 = modulusBigInteger;
    
    return true;
}

juce::BigInteger PEMFormatKey::convertANS1NodeToBigInteger(ASN1::Ptr sequence)
{
    juce::MemoryBlock exponentBlock;
    exponentBlock.setSize(sequence->length);
    sequence->stream->setPosition(sequence->stream->getPosition() + sequence->header);
    sequence->stream->read(exponentBlock.getData(), static_cast<int>(sequence->length));
    auto exponentHexStr = juce::String::toHexString(exponentBlock.getData(),
                                                    static_cast<int>(sequence->length));
    exponentHexStr = exponentHexStr.removeCharacters(" ");

    auto exponentBigInteger = juce::BigInteger();
    exponentBigInteger.parseString(exponentHexStr, 16);
    
    return exponentBigInteger;
}

bool PEMFormatKey::loadPrivateKey(ASN1::Ptr asn1x509)
{
    /*
     Toss a PEM private key into this link
     http://lapo.it/asn1js/
     
     you'll see the following:
     
     SEQUENCE (3 elem)
        Integer
        Sequence (2 elem)
            Object identifier
            NULL
        Octet String
            Sequence (9 elem)
                Integer - version
                Integer - modulus
                Integer - public exponent
                Integer - private exponent
                Integer - prime1
                Integer - prime2
                Integer - exponent1
                Integer - exponent2
                Integer - coefficient
     
     Octet String sequence described here:
     https://datatracker.ietf.org/doc/html/rfc3447#appendix-A:~:text=A.1.2%20RSA-,private,-key%20syntax%0A%0A%20%20%20An
     
     TODO: verify object identifier is 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
     */
    jassert(asn1x509->sub.size() == 3);
    if( asn1x509->sub.size() != 3)
    {
        DBG( "invalid private key format!" );
        jassertfalse;
        return false;
    }
    
    auto integer = asn1x509->sub[0];
    auto sequence1 = asn1x509->sub[1];
    jassert(sequence1->sub.size() == 2 );
    if( sequence1->sub.size() != 2 )
    {
        DBG( "invalid private key Object Identifier format!" );
        jassertfalse;
        return false;
    }
    auto octetString = asn1x509->sub[2];
    jassert(octetString->sub.size() == 1);
    if( octetString->sub.size() != 1 )
    {
        DBG( "invalid private key Octet String format!" );
        jassertfalse;
        return false;
    }
    
    auto sequence2 = octetString->sub[0];
    jassert(sequence2->sub.size() > 0 );
    //check the version
    auto versionBI = convertANS1NodeToBigInteger(sequence2->sub[0]);
    if( versionBI.toInteger() != 0 )
    {
        DBG( "only version 0 of the RSA Private Key Syntax is supported" );
        jassertfalse;
        return false;
    }
    
    jassert(sequence2->sub.size() == 9);
    if( sequence2->sub.size() != 9 )
    {
        DBG( "invalid RSA Private Key!!" );
        jassertfalse;
        return false;
    }
    
    auto n = convertANS1NodeToBigInteger(sequence2->sub[1]); // modulus
    auto e = convertANS1NodeToBigInteger(sequence2->sub[2]); //publicExponent
    auto d = convertANS1NodeToBigInteger(sequence2->sub[3]); //privateExponent
    auto p = convertANS1NodeToBigInteger(sequence2->sub[4]); //prime1
    auto q = convertANS1NodeToBigInteger(sequence2->sub[5]); //prime2
    auto d_mod_p_minus_1_extracted = convertANS1NodeToBigInteger(sequence2->sub[6]); //exponent1
    auto d_mod_q_minus_1_extracted = convertANS1NodeToBigInteger(sequence2->sub[7]); //exponent2
    auto q_pow_neg1_mod_p = convertANS1NodeToBigInteger(sequence2->sub[8]); //coefficient
    
    /*
     confirm that the math checks out for:
     
     n = p * q
     
     e * d == 1 mod ( leastCommonMultiple(p-1, q-1) )
     
     e^(-1) mod(p-1) == d mod (p-1)
     e^(-1) mod(q-1) == d mod (q-1)
    */
    jassert( n == p * q ); // n = p . q
    if( n.compare(p*q) != 0 )
    {
        DBG( "failed math check: n == p * q" );
        jassertfalse;
        return false;
    }
    
    //compute LCM=lcm(p-1, q-1), e * d
    //confirm that e * d mod (LCM) == 1 mod (LCM)
    auto ed( e * d );
    auto one = juce::BigInteger(1);
    auto lcm = computeLeastCommonMultiple(p - 1, q - 1);
    one.exponentModulo(1, lcm);
    ed.exponentModulo(1, lcm);
    jassert( ed.compare( one ) == 0 );
    if( ed.compare(one) != 0 )
    {
        DBG( "failed math check: e * d mod (lcm(p-1, q-1)) == 1 mod (lcm(p-1, q-1))" );
        jassertfalse;
        return false;
    }
    
    //Compute [e^-1 mod (p - 1)] and [d mod (p - 1)]
    //confirm that [e^-1 mod (p - 1)] == [d mod (p - 1)]
    auto e_invMod_p_minus1_computed(e);
    e_invMod_p_minus1_computed.inverseModulo( p - 1);
    auto d_mod_p_minus1_computed(d);
    d_mod_p_minus1_computed.exponentModulo(1, p - 1);
    //compare the computed values
    jassert( e_invMod_p_minus1_computed.compare(d_mod_p_minus1_computed) == 0 );
    if( e_invMod_p_minus1_computed.compare(d_mod_p_minus1_computed) != 0 )
    {
        DBG( "failed math check: e^-1 mod (p - 1) == d mod (p - 1)" );
        jassertfalse;
        return false;
    }
    
    //compare the extracted value with the computed value
    jassert( d_mod_p_minus1_computed.compare(d_mod_p_minus_1_extracted) == 0 );
    if( d_mod_p_minus1_computed.compare(d_mod_p_minus_1_extracted) != 0 )
    {
        DBG( "computed value [d mod (p - 1)] does not match extracted value!" );
        jassertfalse;
        return false;
    }
    
    //compute e^-1 mod (q - 1) and d mod (q - 1)
    //confirm that [e^-1 mod (q - 1)] == [d mod (q - 1)]
    auto e_invMod_q_minus1_computed(e);
    e_invMod_q_minus1_computed.inverseModulo(q - 1);
    auto d_mod_q_minus1_computed(d);
    d_mod_q_minus1_computed.exponentModulo(1, q - 1);
    //compare the computed values
    jassert( e_invMod_q_minus1_computed.compare(d_mod_q_minus1_computed) == 0 );
    if( e_invMod_q_minus1_computed.compare(d_mod_q_minus1_computed) != 0 )
    {
        DBG( "failed math check: e^-1 mod (q - 1) == d mod (q - 1)" );
        jassertfalse;
        return false;
    }
    //compare the extracted value with the computed value
    jassert( d_mod_q_minus1_computed.compare(d_mod_q_minus_1_extracted) == 0);
    if( d_mod_q_minus1_computed.compare(d_mod_q_minus_1_extracted) != 0 )
    {
        DBG( "computed value [d mod (q - 1)] does not match extracted value!" );
        jassertfalse;
        return false;
    }
    
    //compute q^-1 mod p
    auto q_invMod_p_computed(q);
    q_invMod_p_computed.inverseModulo(p);
    //confirm that computed value equals extracted value
    jassert( q_invMod_p_computed.compare(q_pow_neg1_mod_p) == 0);
    if( q_invMod_p_computed.compare(q_pow_neg1_mod_p) != 0 )
    {
        DBG( "computed value [q^-1 mod p] does not match extracted value!" );
        jassertfalse;
        return false;
    }
    
    part1 = d;
    part2 = n;
    
    return true;
}

juce::BigInteger PEMFormatKey::computeLeastCommonMultiple(const juce::BigInteger &a, const juce::BigInteger &b)
{
    auto gcd = a.findGreatestCommonDivisor(b);
    auto absAB = a * b;
    if( absAB.isNegative() )
        absAB *= -1;
    
    return absAB / gcd;
}

juce::String PEMFormatKey::decryptBase64String(juce::String base64)
{
    auto confirmationBlock = PEMHelpers::convertPEMStringToPEMMemoryBlock(base64);
    auto confirmationHex = juce::String::toHexString(confirmationBlock.getData(),
                                                     static_cast<int>(confirmationBlock.getSize()));
    juce::BigInteger confirmationBigInt;
    confirmationBigInt.parseString(confirmationHex, 16);
    applyToValue(confirmationBigInt);
    
    auto decrypted = confirmationBigInt.toMemoryBlock();
    auto decryptedString = juce::String::createStringFromData(decrypted.getData(), static_cast<int>(decrypted.getSize()));
    
    //see https://forum.juce.com/t/string-reverse-method/23582/20?u=matkatmusic
    auto stringReverser = [](const juce::String& in)
    {
        auto inBegin = in.getCharPointer();
        auto inPtr = inBegin.findTerminatingNull();
        
        juce::String out;
        
        if (inPtr != inBegin)
        {
            out.preallocateBytes(inPtr - inBegin);
            
            auto outPtr = out.getCharPointer();
            
            while (inPtr != inBegin)
            {
                --inPtr;
                outPtr.write(*inPtr);
            }
            
            outPtr.writeNull();
        }
        
        return out;
    };
    
    decryptedString = stringReverser(decryptedString);
    
    return decryptedString;
}
