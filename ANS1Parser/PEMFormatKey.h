/*
  ==============================================================================

    PEMFormatKey.h
    Created: 25 Jun 2022 12:15:45pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>

#include "ASN1Decoder.h"

struct PEMFormatKey : juce::RSAKey
{
    void loadFromPEMFormattedString(juce::String str);
    juce::String decryptBase64String(juce::String base64);
    juce::BigInteger getPart1() const { return part1; }
    juce::BigInteger getPart2() const { return part2; }
private:
    bool loadPublicKey(ASN1::Ptr asn1x509);
    bool loadPrivateKey(ASN1::Ptr asn1x509);
    juce::BigInteger convertANS1NodeToBigInteger(ASN1::Ptr exponent);
    static juce::BigInteger computeLeastCommonMultiple(const juce::BigInteger& a,
                                                const juce::BigInteger& b);
};

struct ConvertibleRSAKey : juce::RSAKey
{
    //adds the ability to convert to the PEM format
    void createKeyPair(const int numBits, const int* randomSeeds, const int numRandomSeeds);
    juce::String getPublicKeyAsPEM();
    juce::String getPrivateKeyAsPEM();
private:
    juce::RSAKey publicKey, privateKey;
    juce::BigInteger p, q;
    
    static juce::BigInteger findBestCommonDivisor (const juce::BigInteger& p, const juce::BigInteger& q);
};
