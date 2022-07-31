/*
  ==============================================================================

    RSA.cpp
    Created: 15 Jul 2022 4:02:48pm
    Author:  Matkat Music LLC

  ==============================================================================
*/

#include "RSA.h"
namespace Forge
{
namespace RSA
{
Forge::RSA::Validator::Ptr getRSAPublicKeyValidator()
{
//var rsaPublicKeyValidator = {
  // RSAPublicKey
//  name: 'RSAPublicKey',
//  tagClass: asn1.Class.UNIVERSAL,
//  type: asn1.Type.SEQUENCE,
//  constructed: true,
//  value: [{
//    // modulus (n)
//    name: 'RSAPublicKey.modulus',
//    tagClass: asn1.Class.UNIVERSAL,
//    type: asn1.Type.INTEGER,
//    constructed: false,
//    capture: 'publicKeyModulus'
//  }, {
//    // publicExponent (e)
//    name: 'RSAPublicKey.exponent',
//    tagClass: asn1.Class.UNIVERSAL,
//    type: asn1.Type.INTEGER,
//    constructed: false,
//    capture: 'publicKeyExponent'
//  }]
    
    Validator::Ptr modulus = new Validator();
    modulus->name = "RSAPublicKey.modulus";
    modulus->tagClass = ASN1::Class::UNIVERSAL;
    modulus->type = ASN1::Type::INTEGER;
    modulus->constructed = false;
    modulus->capture = "publicKeyModulus";
    
    Validator::Ptr exponent = new Validator();
    exponent->name = "RSAPublicKey.exponent";
    exponent->tagClass = ASN1::Class::UNIVERSAL;
    exponent->type = ASN1::Type::INTEGER;
    exponent->constructed = false;
    exponent->capture = "publicKeyExponent";
    
    Validator::Ptr rsaPublicKeyValidator = new Validator();
    rsaPublicKeyValidator->name = "RSAPublicKey";
    rsaPublicKeyValidator->tagClass = ASN1::Class::UNIVERSAL;
    rsaPublicKeyValidator->type = ASN1::Type::SEQUENCE;
    rsaPublicKeyValidator->constructed = true;
    rsaPublicKeyValidator->value =
    {
        modulus,
        exponent
    };
    
    return rsaPublicKeyValidator;
}

Forge::RSA::Validator::Ptr getPublicKeyValidator()
{
    /*
     // validator for an SubjectPublicKeyInfo structure
     // Note: Currently only works with an RSA public key
     var publicKeyValidator = forge.pki.rsa.publicKeyValidator = {
       name: 'SubjectPublicKeyInfo',
       tagClass: asn1.Class.UNIVERSAL,
       type: asn1.Type.SEQUENCE,
       constructed: true,
       captureAsn1: 'subjectPublicKeyInfo',
       value: [{
         name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.SEQUENCE,
         constructed: true,
         value: [{
           name: 'AlgorithmIdentifier.algorithm',
           tagClass: asn1.Class.UNIVERSAL,
           type: asn1.Type.OID,
           constructed: false,
           capture: 'publicKeyOid'
         }]
       }, {
         // subjectPublicKey
         name: 'SubjectPublicKeyInfo.subjectPublicKey',
         tagClass: asn1.Class.UNIVERSAL,
         type: asn1.Type.BITSTRING,
         constructed: false,
         value: [{
           // RSAPublicKey
           name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
           tagClass: asn1.Class.UNIVERSAL,
           type: asn1.Type.SEQUENCE,
           constructed: true,
           optional: true,
           captureAsn1: 'rsaPublicKey'
         }]
       }]
     };
     */
    Validator::Ptr SubjectPublicKeyInfo = new Validator();
//#if false
    
    SubjectPublicKeyInfo->name = "SubjectPublicKeyInfo";
    SubjectPublicKeyInfo->tagClass = ASN1::Class::UNIVERSAL;
    SubjectPublicKeyInfo->type = ASN1::Type::SEQUENCE;
    SubjectPublicKeyInfo->constructed = true;
    SubjectPublicKeyInfo->captureAsn1 = "subjectPublicKeyInfo";
    
    Validator::Ptr AlgorithmIdentifier = new Validator();
    AlgorithmIdentifier->name = "SubjectPublicKeyInfo.AlgorithmIdentifier";
    AlgorithmIdentifier->tagClass = ASN1::Class::UNIVERSAL;
    AlgorithmIdentifier->type = ASN1::Type::SEQUENCE;
    AlgorithmIdentifier->constructed = true;
    
    Validator::Ptr algorithm = new Validator();
    algorithm->name = "AlgorithmIdentifier.algorithm";
    algorithm->tagClass = ASN1::Class::UNIVERSAL;
    algorithm->type = ASN1::Type::OID;
    algorithm->constructed = false;
    algorithm->captureAsn1 = "publicKeyOid";
    
    AlgorithmIdentifier->value =
    {
        algorithm
    };
    
    Validator::Ptr subjectPublicKey = new Validator();
    subjectPublicKey->name = "SubjectPublicKeyInfo.subjectPublicKey";
    subjectPublicKey->tagClass = ASN1::Class::UNIVERSAL;
    subjectPublicKey->type = ASN1::Type::BITSTRING;
    subjectPublicKey->constructed = false;
    
    Validator::Ptr RSAPublicKey = new Validator();
    RSAPublicKey->name = "SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey";
    RSAPublicKey->tagClass = ASN1::Class::UNIVERSAL;
    RSAPublicKey->type = ASN1::Type::SEQUENCE;
    RSAPublicKey->constructed = true;
    RSAPublicKey->optional = true;
    RSAPublicKey->captureAsn1 = "rsaPublicKey";
    subjectPublicKey->value =
    {
        RSAPublicKey
    };
    
    SubjectPublicKeyInfo->value =
    {
        AlgorithmIdentifier,
        subjectPublicKey,
    };

    return SubjectPublicKeyInfo;
}

} //end namespace RSA
} //end namespace Forge
