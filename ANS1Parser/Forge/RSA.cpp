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
namespace PKI
{
namespace V2
{
/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes.
 *
 * @param b the big integer to convert.
 *
 * @return the bytes.
 */
juce::MemoryBlock _bnToBytes(const juce::BigInteger& b)
{
    auto mb = b.toMemoryBlock();
    
    juce::MemoryBlock output;
    
    {
        juce::MemoryOutputStream mos(output, false);
        
        for(int i = mb.getSize() - 1; i >= 0; --i )
        {
            mos.writeByte(mb[i]); //write to output in Big-Endian (aka reversed) order
        }
    } //mos goes out of scope, calls 'flush()', finishing the write operation to 'output'

    auto hex = juce::String::toHexString(output.getData(), output.getSize(), 0);
    if( static_cast<juce::uint8>(output[0]) >= 0x80 )
    {
        hex = "00" + hex;
        //insert the 00 at the beginning of `output`
        decltype(output) tempMemBlock;
        {
            juce::MemoryOutputStream mos(tempMemBlock, false);
            mos.writeByte(0);
        } //mos goes out of scope, calls 'flush()', finishing the write operation to 'tempMemBlock'
        
        //add all of 'output' to tempMemBlock
        tempMemBlock.append(output.getData(), output.getSize());
        
        //replace output with tempMemBlock
        output = tempMemBlock;
    }
    
    DBG( "hex: " << hex );
    
    return output;
}
} //end namespace V2
} //end namespace PKI
namespace RSA
{
namespace V2
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
juce::var getRSAPublicKeyValidator()
{
    juce::var v( new juce::DynamicObject() );
    auto* obj = v.getDynamicObject();
    
    //  name: 'RSAPublicKey',
    obj->setProperty("name", "RSAPublicKey");
    //  tagClass: asn1.Class.UNIVERSAL,
    obj->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
    //  type: asn1.Type.SEQUENCE,
    obj->setProperty("type", static_cast<int>(ASN1::Type::SEQUENCE));
    //  constructed: true,
    obj->setProperty("constructed", true);
    //  value: [{
    //    // modulus (n)
    juce::var modulus ( new juce::DynamicObject() );
    auto* mod = modulus.getDynamicObject();
    //    name: 'RSAPublicKey.modulus',
    mod->setProperty("name", "RSAPublicKey.modulus");
    //    tagClass: asn1.Class.UNIVERSAL,
    mod->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
    //    type: asn1.Type.INTEGER,
    mod->setProperty("type", static_cast<int>(ASN1::Type::INTEGER));
    //    constructed: false,
    mod->setProperty("constructed", false);
    //    capture: 'publicKeyModulus'
    mod->setProperty("capture", "publicKeyModulus");
    //  }, {
    //    // publicExponent (e)
    juce::var publicExponent ( new juce::DynamicObject() );
    auto exp = publicExponent.getDynamicObject();
    //    name: 'RSAPublicKey.exponent',
    exp->setProperty("name", "RSAPublicKey.exponent");
    //    tagClass: asn1.Class.UNIVERSAL,
    exp->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
    //    type: asn1.Type.INTEGER,
    exp->setProperty("type", static_cast<int>(ASN1::Type::INTEGER));
    //    constructed: false,
    exp->setProperty("constructed", false);
    //    capture: 'publicKeyExponent'
    exp->setProperty("capture", "publicKeyExponent");
    //  }]
    
    obj->setProperty("value", juce::Array<juce::var>{modulus, publicExponent});
    return v;
}

juce::var getPublicKeyValidator()
{
    juce::var v ( new juce::DynamicObject() );
    auto* o = v.getDynamicObject();
     // validator for an SubjectPublicKeyInfo structure
     // Note: Currently only works with an RSA public key
//    var publicKeyValidator = forge.pki.rsa.publicKeyValidator = {
//        name: 'SubjectPublicKeyInfo',
//    tagClass: asn1.Class.UNIVERSAL,
    o->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
//    type: asn1.Type.SEQUENCE,
    o->setProperty("type", static_cast<int>(ASN1::Type::SEQUENCE));
//    constructed: true,
    o->setProperty("constructed", true);
//    captureAsn1: 'subjectPublicKeyInfo',
    o->setProperty("captureAsn1", "subjectPublickeyInfo");
//    value:
//    [{
        juce::var algoIdentifier( new juce::DynamicObject() );
        auto* agido = algoIdentifier.getDynamicObject();
//        name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
        agido->setProperty("name", "SubjectPublicKeyInfo.AlgorithmIdentifier");
//        tagClass: asn1.Class.UNIVERSAL,
        agido->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
//        type: asn1.Type.SEQUENCE,
        agido->setProperty("type", static_cast<int>(ASN1::Type::SEQUENCE));
//        constructed: true,
        agido->setProperty("constructed", true);
//        value:
//        [{
            juce::var algorithm( new juce::DynamicObject() );
            auto* algo = algorithm.getDynamicObject();
//            name: 'AlgorithmIdentifier.algorithm',
            algo->setProperty("name", "AlgorithmIdentifier.algorithm");
//            tagClass: asn1.Class.UNIVERSAL,
            algo->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
//            type: asn1.Type.OID,
            algo->setProperty("type", static_cast<int>(ASN1::Type::OID));
//            constructed: false,
            algo->setProperty("constructed", false);
//            capture: 'publicKeyOid'
            algo->setProperty("capture", "publicKeyOid");
//        }]
        agido->setProperty("value", juce::Array<juce::var>({algorithm}));
//     },
//        {
            // subjectPublicKey
            juce::var subjectPublicKey( new juce::DynamicObject() );
            auto* spko = subjectPublicKey.getDynamicObject();
        
//        name: 'SubjectPublicKeyInfo.subjectPublicKey',
            spko->setProperty("name", "SubjectPublicKeyInfo.subjectPublicKey");
//        tagClass: asn1.Class.UNIVERSAL,
            spko->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
//        type: asn1.Type.BITSTRING,
            spko->setProperty("type", static_cast<int>(ASN1::Type::BITSTRING));
//        constructed: false,
            spko->setProperty("constructed", false);
//        value: [{
        // RSAPublicKey
                juce::var RSAPublicKey( new juce::DynamicObject() );
                auto* rpko = RSAPublicKey.getDynamicObject();
//            name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
                rpko->setProperty("name", "SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey");
//            tagClass: asn1.Class.UNIVERSAL,
                rpko->setProperty("tagClass", static_cast<int>(ASN1::Class::UNIVERSAL));
//            type: asn1.Type.SEQUENCE,
                rpko->setProperty("type", static_cast<int>(ASN1::Type::SEQUENCE));
//            constructed: true,
                rpko->setProperty("constructed", true);
//            optional: true,
                rpko->setProperty("optional", true);
//            captureAsn1: 'rsaPublicKey'
                rpko->setProperty("captureAsn1", "rsaPublicKey");
//        }]
        spko->setProperty("value", juce::Array<juce::var>({RSAPublicKey}));
//    }]
    o->setProperty("value", juce::Array<juce::var>(algoIdentifier, subjectPublicKey));
//    };
    return v;
}
} //end namespace V2
namespace V1
{
Validator::Ptr getRSAPublicKeyValidator()
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

Validator::Ptr getPublicKeyValidator()
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
} //end namespace V1
} //end namespace RSA
} //end namespace Forge
