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
private:
    bool loadPublicKey(ASN1::Ptr asn1x509);
    bool loadPrivateKey(ASN1::Ptr asn1x509);
    juce::BigInteger convertANS1NodeToBigInteger(ASN1::Ptr exponent);
    static juce::BigInteger computeLeastCommonMultiple(const juce::BigInteger& a,
                                                const juce::BigInteger& b);
};
