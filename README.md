# OpenSSLToJuceRSAKey
a collection of classes that convert OpenSSL-generated X509 Public and Private keys into the juce::RSAKey format

This is a port of JS code from the Forge Framework.
Only code that was needed to migrate the PEM -> Key -> PEM functionality was ported. 

Forge is found here: https://github.com/digitalbazaar/forge
https://github.com/digitalbazaar/forge/tree/main/lib

usage: 
```
//note the paths account for this repo being used as a submodule
#include "../OpenSSLToJuceRSAKey/ANS1Parser/Forge/Pem.h"
#include "../OpenSSLToJuceRSAKey/ANS1Parser/Forge/ASN1.h"
#include "../OpenSSLToJuceRSAKey/ANS1Parser/Forge/RSA.h"
#include "../OpenSSLToJuceRSAKey/ANS1Parser/Forge/x509.h"
#include "../OpenSSLToJuceRSAKey/ANS1Parser/AccessibleKey.h" 

juce::String publicKey ( "-----BEGIN PUBLIC KEY-----...." );
juce::String privateKey ( "-----BEGIN PRIVATE KEY-----...." );

auto pubKey = testPublicKey(publicKey);
auto privKey = testPrivateKey(privateKey);

performEncryptDecryptTest(pubKey, privKey, "This is a test messages");

```
`testPublicKey` looks like this:
```
AccessiblePublicKey testPublicKey(juce::File publicKey)
{
    //copy key into memoryBlock, confirming length, then convert it to string.
    juce::FileInputStream fis(publicKey);
    juce::MemoryBlock block;
    auto len = fis.getTotalLength();
    block.ensureSize(len);
    auto numRead = fis.read(block.getData(), static_cast<int>(len));
    jassert(numRead == len);
    auto publicKeyPemInput = block.toString();
    
    DBG( publicKeyPemInput.trim() );
    
    //convert PEM file into juce::RSAKey-derived class
    auto key = Forge::PKI::V2::publicKeyFromPem<AccessiblePublicKey>(publicKeyPemInput);
    
    //convert juce::RSAKey-derived class instance back into PEM format
    auto pemData = Forge::PKI::V2::publicKeyToPem(key);
    
    DBG( "\n\n\nPemData:\n");
    DBG( pemData);
    
    //confirm that PEM data matches original input. 
    pemData = pemData.replace("\r\n", "\n");
    if( publicKeyPemInput != pemData )
    {
        DBG("error, outputs don't match" );
    }
    else
    {
        DBG("encoding <=> decoding PEM works!" );
    }
    
    return key;
}
```
`testPrivateKey` looks like this:
```
AccessiblePrivateKey testPrivateKey(juce::File file)
{
    //copy key into memoryBlock, confirming length, then convert it to string.
    juce::FileInputStream fis(file);
    juce::MemoryBlock block;
    auto len = fis.getTotalLength();
    block.ensureSize(len);
    auto numRead = fis.read(block.getData(), static_cast<int>(len));
    jassert(numRead == len);
    auto privateKeyPemInput = block.toString();

    // convert a PEM-formatted private key to a Forge private key
    auto privateKey = Forge::PKI::V2::privateKeyFromPem<AccessiblePrivateKey>(privateKeyPemInput);

    DBG( "\n\n\n\n" ); 
    // convert a Forge private key to an ASN.1 RSAPrivateKey
    auto rsaPrivateKey = Forge::PKI::V2::privateKeyToAsn1(privateKey);
   
    // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
    auto privateKeyInfo = Forge::PKI::V2::wrapRsaPrivateKey(rsaPrivateKey);
    
    // convert a PKCS#8 ASN.1 PrivateKeyInfo to PEM
    auto pemData = Forge::PKI::V2::privateKeyInfoToPem<juce::String>(privateKeyInfo);
    
    DBG( "\n\n\nPemData:\n");
    DBG( pemData );
    
    //confirm that PEM data matches original input. 
    pemData = pemData.replace("\r\n", "\n");
    if( privateKeyPemInput != pemData ) 
    {
        DBG( "error, outputs don't match" );
    }
    else
    {
        DBG("encoding <=> decoding PEM works!" );
    }
    
    return privateKey;
}
```
`performEncryptionTest` looks like this:
```
void performEncryptDecryptTest(const AccessiblePublicKey& publicKey,
                               const AccessiblePrivateKey& privateKey,
                               juce::String message)
{
    DBG( "message: " << message );
    //you can also get the public key this way
    auto pubKey = privateKey.getDerivedPublicKey(); 
    
    
    //load the message into a memoryblock
    juce::MemoryBlock memBlock;
    memBlock.setSize(message.length());
    memBlock.copyFrom(message.getCharPointer(), 0, message.length());
    
    DBG( "message as Hex: " <<  juce::String::toHexString(memBlock.getData(),
                                                          memBlock.getSize(),
                                                          0));
    //load the memory block into a big integer
    juce::BigInteger value;
    value.parseString(juce::String::toHexString(memBlock.getData(),
                                                memBlock.getSize(),
                                                0),
                      16);
    
    //encode the data
    publicKey.applyToValue(value);
    DBG( "encoded hex data: " << value.toString(16) );
    
    //decode the data
    privateKey.applyToValue(value);
    DBG( "decoded hex data: " << value.toString(16) );
    
    //convert from hex -> String
    juce::MemoryBlock mb = value.toMemoryBlock();

    //the data may need to be reversed.  
    //this does the job for reversing ASCII strings, but may not be the best/safest way
    
    auto begin = static_cast<char*>(mb.getData());
    std::reverse(begin, begin + mb.getSize());
    
    //confirm the encoding/decoding works
    auto decodedString = mb.toString();
    DBG( "decoded: " << decodedString );
    if( message != decodedString )
    {
        jassertfalse;
    }
    else
    {
        DBG( "encoding -> decoding works as expected!" );
    }
    
}
