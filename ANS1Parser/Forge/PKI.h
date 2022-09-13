/*
  ==============================================================================

    PKI.h
    Created: 15 Jul 2022 4:02:56pm
    Author:  Matkat Music LLC

  ==============================================================================
*/

#pragma once
#include <JuceHeader.h>

#include "Pem.h"
#include "ASN1.h"
#include "RSA.h"
/*
 a port of https://github.com/digitalbazaar/forge/blob/main/lib/pki.js
 */
#if false

/**
 * Javascript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
var forge = require('./forge');
require('./asn1');
require('./oids');
require('./pbe');
require('./pem');
require('./pbkdf2');
require('./pkcs12');
require('./pss');
require('./rsa');
require('./util');
require('./x509');

// shortcut for asn.1 API
var asn1 = forge.asn1;

/* Public Key Infrastructure (PKI) implementation. */
var pki = module.exports = forge.pki = forge.pki || {};

/**
 * NOTE: THIS METHOD IS DEPRECATED. Use pem.decode() instead.
 *
 * Converts PEM-formatted data to DER.
 *
 * @param pem the PEM-formatted data.
 *
 * @return the DER-formatted data.
 */
pki.pemToDer = function(pem) {
  var msg = forge.pem.decode(pem)[0];
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert PEM to DER; PEM is encrypted.');
  }
  return forge.util.createBuffer(msg.body);
};

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 *
 * @return the private key.
 */
#endif

/*
pki.privateKeyFromPem = function(pem) {
  var msg = forge.pem.decode(pem)[0];

  if(msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    var error = new Error('Could not convert private key from PEM; PEM ' +
      'header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".');
    error.headerType = msg.type;
    throw error;
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert private key from PEM; PEM is encrypted.');
  }

  // convert DER to ASN.1 object
  var obj = asn1.fromDer(msg.body);

  return pki.privateKeyFromAsn1(obj);
};
 */
namespace Forge
{
namespace PKI
{
namespace V2
{
template<typename KeyType>
KeyType privateKeyFromPem(juce::String pem)
{
    auto decoded = Forge::PEM::V2::decode(pem); //this needs to return an array of NamedValueSet instances.
    if( std::distance(decoded.begin(), decoded.end()) == 0 )
    {
        jassertfalse;
        return {};
    }
    
    auto msg = decoded[0];
    
    if(msg.contains("type") && msg.getVarPointer("type")->isString() )
    {
        auto type = msg.getVarPointer("type")->toString();
        if( type != "PRIVATE KEY" && type != "RSA PRIVATE KEY" )
        {
            DBG("Could not convert private key from PEM; PEM header type is not \"PRIVATE KEY\" or \"RSA PRIVATE KEY\".");
            jassertfalse;
            return {};
        }
    }
    
    if( msg.contains("procType") &&
       msg.getVarPointer("procType")->isString() &&
       msg.getVarPointer("procType")->toString() == "ENCRYPTED" )
    {
        DBG( "Could not convert private key from PEM; PEM is encrypted." );
        jassertfalse;
        return {};
    }
    
    jassert(msg.contains("body"));
    auto bodyPtr = msg.getVarPointer("body");
    jassert(bodyPtr->isBinaryData());
    auto body = *bodyPtr->getBinaryData();
    DBG( "message body length:" );
    DBG( body.getSize() );
    auto obj = Forge::ASN1::V2::fromDer(body, {});// this returns a juce::var
    
    return Forge::PKI::V2::privateKeyFromAsn1<KeyType>(obj);
}
#if false
/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
pki.privateKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1.toDer(pki.privateKeyToAsn1(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};

/**
 * Converts a PrivateKeyInfo to PEM format.
 *
 * @param pki the PrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
pki.privateKeyInfoToPem = function(pki, maxline) {
  // convert to DER, then PEM-encode
  var msg = {
    type: 'PRIVATE KEY',
    body: asn1.toDer(pki).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};
#endif
template<typename PEMType, typename KeyType>
PEMType privateKeyInfoToPem(const KeyType& pki, int maxLine = 64)
{
    juce::var msg (new juce::DynamicObject() );
    auto* msgdo = msg.getDynamicObject();
    msgdo->setProperty("type", "PRIVATE KEY");
    auto der = Forge::ASN1::V2::toDer(pki); //this should return a var(memoryBlock)
    auto derBytes = *der.getBinaryData();
    msgdo->setProperty("body", derBytes);
    using NV = juce::NamedValueSet::NamedValue;
    auto options = juce::NamedValueSet({NV("maxLine", maxLine)});
    auto pem = Forge::PEM::V2::encode(msg, options);
    
    return pem;
}

} //end namespace V2
}//end namespace PKI
}//end namespace Forge

