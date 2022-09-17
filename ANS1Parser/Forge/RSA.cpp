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
    // prepend 0x00 if first byte >= 0x80
    auto hex = b.toString(16);                                      //var hex = b.toString(16);
    if(hex.substring(0, 1)[0] >= '8')                               //if(hex[0] >= '8')
    {                                                               //{
        hex = "00" + hex;                                           //    hex = '00' + hex;
    }                                                               //}
    DBG( "hex: " << hex );                                          //console.log(`hex: ${hex}`);
    auto bytes = juce::MemoryBlock();                               //var bytes = forge.util.hexToBytes(hex);
    
    /*
     loadFromHexString() expects the string to have a length that is a multiple of 2.
     This is not stated in the documentation, but the implementation reveals this. 
     */
    if( hex.length() % 2 != 0 )
    {
        hex = "0" + hex; 
    }
    bytes.loadFromHexString(hex);
                                                                    //
    // ensure integer is minimally-encoded                          //// ensure integer is minimally-encoded
    if(bytes.getSize() > 1 &&                                       //if(bytes.length > 1 &&
       // leading 0x00 for positive integer                         //   // leading 0x00 for positive integer
       ((static_cast<juce::uint8>(bytes[0]) == 0 &&                 //   ((bytes.charCodeAt(0) === 0 &&
         (static_cast<juce::uint8>(bytes[1]) & 0x80) == 0) ||       //     (bytes.charCodeAt(1) & 0x80) === 0) ||
        // leading 0xFF for negative integer                        //    // leading 0xFF for negative integer
        (static_cast<juce::uint8>(bytes[0]) == 0xFF &&              //    (bytes.charCodeAt(0) === 0xFF &&
         (static_cast<juce::uint8>(bytes[1]) & 0x80) == 0x80)))     //     (bytes.charCodeAt(1) & 0x80) === 0x80)))
    {                                                               //{
        juce::MemoryBlock trimmed;
        {
            juce::MemoryInputStream mis(bytes, false);
            mis.readByte();
            mis.readIntoMemoryBlock(trimmed);
        }
        DBG( "_bnToBytes trimmed result: " << juce::String::toHexString(trimmed.getData(), trimmed.getSize(), 0));
        return trimmed;                                             //    return bytes.substr(1);
        
    }                                                               //}
    
    DBG( "_bnToBytes result: " << juce::String::toHexString(bytes.getData(), bytes.getSize(), 0));
    return bytes;                                                   //return bytes;
    
}
} //end namespace V2
namespace V1
{
juce::String findOID(juce::String oidToFind)
{
    const auto& oids = PKI::oids();
    for( auto [k, o] : oids )
    {
        if( o == oidToFind )
        {
            return k; //return the long version ID code xxxxxx.xx.xxxx.xx.xx.x.x
        }
    }
    
    jassertfalse;
    return {};
}
} //end namespace V1
} //end namespace PKI
namespace RSA
{
namespace V2
{
template<typename PropsType>
juce::NamedValueSet makeProps(const PropsType& props)
{
    juce::NamedValueSet nvs;
    
    for( const auto& prop : props )
    {
        nvs.set(prop.name, prop.value);
    }
    
    return nvs;
}

juce::var createObject(std::vector<juce::NamedValueSet::NamedValue> props)
{
    auto obj = juce::var( new juce::DynamicObject() );
    auto* o = obj.getDynamicObject();
    
    auto& nvs = o->getProperties();
    nvs = makeProps(props);
    
    return obj;
}
//var rsaPublicKeyValidator =
//{
//  // RSAPublicKey
//  name: 'RSAPublicKey',
//  tagClass: asn1.Class.UNIVERSAL,
//  type: asn1.Type.SEQUENCE,
//  constructed: true,
//  value:
//  [
//  {
//    // modulus (n)
//    name: 'RSAPublicKey.modulus',
//    tagClass: asn1.Class.UNIVERSAL,
//    type: asn1.Type.INTEGER,
//    constructed: false,
//    capture: 'publicKeyModulus'
//  },
//  {
//    // publicExponent (e)
//    name: 'RSAPublicKey.exponent',
//    tagClass: asn1.Class.UNIVERSAL,
//    type: asn1.Type.INTEGER,
//    constructed: false,
//    capture: 'publicKeyExponent'
//  }
//  ]
//};
juce::var getRSAPublicKeyValidator()
{
    auto rsaPublicKeyValidator =                                            //var rsaPublicKeyValidator =
    createObject({                                                          //{
        // RSAPublicKey                                                     //    // RSAPublicKey
        {"name", "RSAPublicKey"},                                           //    name: 'RSAPublicKey',
        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},             //    tagClass: asn1.Class.UNIVERSAL,
        {"type", static_cast<int>(ASN1::Type::SEQUENCE)},                   //    type: asn1.Type.SEQUENCE,
        {"constructed", true},                                              //    constructed: true,
        {"value", juce::Array<juce::var>                                    //    value:
        {                                                                   //    [
            createObject({                                                  //        {
                // modulus (n)                                              //        // modulus (n)
                {"name", "RSAPublicKey.modulus"},                           //            name: 'RSAPublicKey.modulus',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},     //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},            //            type: asn1.Type.INTEGER,
                {"constructed", false},                                     //            constructed: false,
                {"capture", "publicKeyModulus"}                             //            capture: 'publicKeyModulus'
            }),                                                             //        },
            createObject({                                                  //        {
                // publicExponent (e)                                       //        // publicExponent (e)
                {"name", "RSAPublicKey.exponent"},                          //            name: 'RSAPublicKey.exponent',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},     //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},            //            type: asn1.Type.INTEGER,
                {"constructed", false},                                     //            constructed: false,
                {"capture", "publicKeyExponent"}                            //            capture: 'publicKeyExponent'
            })                                                              //        }
        }}                                                                  //    ]
    });                                                                     //};
    
    return rsaPublicKeyValidator;
#if false
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
#endif
}

juce::var getPublicKeyValidator()
{
    auto publicKeyValidator = //var publicKeyValidator = forge.pki.rsa.publicKeyValidator =
    createObject({//{
        {"name", "SubjectPublicKeyInfo"},//    name: 'SubjectPublicKeyInfo',
        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},//    tagClass: asn1.Class.UNIVERSAL,
        {"type", static_cast<int>(ASN1::Type::SEQUENCE)},//    type: asn1.Type.SEQUENCE,
        {"constructed", true},//    constructed: true,
        {"captureAsn1", "subjectPublicKeyInfo"},//    captureAsn1: 'subjectPublicKeyInfo',
        {"value",//    value:
        juce::Array<juce::var>{//    [
            createObject({//        {
                {"name", "SubjectPublicKeyInfo.AlgorithmIdentifier"},//        name: 'SubjectPublicKeyInfo.AlgorithmIdentifier',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},//        tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::SEQUENCE)},//        type: asn1.Type.SEQUENCE,
                {"constructed", true},//        constructed: true,
                {"value",//        value:
                juce::Array<juce::var>{//            [
                    createObject({//                {
                        {"name", "AlgorithmIdentifier.algorithm"},//                name: 'AlgorithmIdentifier.algorithm',
                        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},//                tagClass: asn1.Class.UNIVERSAL,
                        {"type", static_cast<int>(ASN1::Type::OID)},//                type: asn1.Type.OID,
                        {"constructed", false},//                constructed: false,
                        {"capture", "publicKeyOid"}//                capture: 'publicKeyOid'
                    })//                }
                }}//            ]
            }),//        },
            createObject({//        {
            // subjectPublicKey//            // subjectPublicKey
                {"name", "SubjectPublicKeyInfo.subjectPublicKey"},//            name: 'SubjectPublicKeyInfo.subjectPublicKey',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},//            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::BITSTRING)},//            type: asn1.Type.BITSTRING,
                {"constructed", false},//            constructed: false,
                {"value",//            value:
                juce::Array<juce::var>{//            [
                    createObject({//                {
                        // RSAPublicKey//                // RSAPublicKey
                        {"name", "SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey"},//                name: 'SubjectPublicKeyInfo.subjectPublicKey.RSAPublicKey',
                        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},//                tagClass: asn1.Class.UNIVERSAL,
                        {"type", static_cast<int>(ASN1::Type::SEQUENCE)},//                type: asn1.Type.SEQUENCE,
                        {"constructed", true},//                constructed: true,
                        {"optional", true},//                optional: true,
                        {"captureAsn1", "rsaPublicKey"}//                captureAsn1: 'rsaPublicKey'
                    })//                }
                }}//            ]
            })//        }
        }}//    ]
    });//};
    
    return publicKeyValidator;
#if false
    {
    juce::var v ( new juce::DynamicObject() );
    auto* o = v.getDynamicObject();
     // validator for an SubjectPublicKeyInfo structure
     // Note: Currently only works with an RSA public key
//    var publicKeyValidator = forge.pki.rsa.publicKeyValidator = {
//        name: 'SubjectPublicKeyInfo',
    o->setProperty("name", "SubjectPublicKeyInfo");
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
#endif
}

juce::var getPrivateKeyValidator()
{
    auto privateKeyValidator = createObject({ //begin object                    //var privateKeyValidator = {
        // PrivateKeyInfo                                                           // PrivateKeyInfo
        {"name", "PrivateKeyInfo"},                                             //  name: 'PrivateKeyInfo',
        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},                 //  tagClass: asn1.Class.UNIVERSAL,
        {"type", static_cast<int>(ASN1::Type::SEQUENCE)},                       //  type: asn1.Type.SEQUENCE,
        {"constructed", true},                                                  //  constructed: true,
        {"value", juce::Array<juce::var>{ //begin array                         //  value: [
            createObject({//begin object                                        //  {
                // Version (INTEGER)                                                    // Version (INTEGER)
                {"name", "PrivateKeyInfo.version"},                             //      name: 'PrivateKeyInfo.version',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //      tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //      type: asn1.Type.INTEGER,
                {"constructed", false},                                         //      constructed: false,
                {"capture", "privateKeyVersion"}                                //      capture: 'privateKeyVersion'
            }), //end object                                                    //  },
            createObject({ //begin object                                       //  {
                // privateKeyAlgorithm                                                  // privateKeyAlgorithm
                {"name", "PrivateKeyInfo.privateKeyAlgorithm"},                 //      name: 'PrivateKeyInfo.privateKeyAlgorithm',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //      tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::SEQUENCE)},               //      type: asn1.Type.SEQUENCE,
                {"constructed", true},                                          //      constructed: true,
                {"value", juce::Array<juce::var>{//begin array                  //      value: [
                    createObject({//begin object                                //      {
                        {"name", "AlgorithmIdentifier.algorithm"},              //          name: 'AlgorithmIdentifier.algorithm',
                        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)}, //          tagClass: asn1.Class.UNIVERSAL,
                        {"type", static_cast<int>(ASN1::Type::OID)},            //          type: asn1.Type.OID,
                        {"constructed", false},                                 //          constructed: false,
                        {"capture", "privateKeyOid"}                            //          capture: 'privateKeyOid'
                    }) //end object                                             //      }
                }}//end array                                                   //      ]
            }), //end object                                                    //  },
            createObject({ //begin object                                       //  {
                // PrivateKey                                                           // PrivateKey
                {"name", "PrivateKeyInfo"},                                     //      name: 'PrivateKeyInfo',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //      tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::OCTETSTRING)},            //      type: asn1.Type.OCTETSTRING,
                {"constructed", false},                                         //      constructed: false,
                {"capture", "privateKey"}                                       //      capture: 'privateKey'
                }) //end object                                                 //  }
        }}//end array                                                           //  ]
    });//end object                                                             //};

    
    return privateKeyValidator;
}

juce::var getRsaPrivateKeyValidator()
{
    auto rsaPrivateKeyValidator = createObject({//begin object                  //var rsaPrivateKeyValidator = {
        // RSAPrivateKey                                                        //    // RSAPrivateKey
        {"name", "RSAPrivateKey"},                                              //    name: 'RSAPrivateKey',
        {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},                 //    tagClass: asn1.Class.UNIVERSAL,
        {"type", static_cast<int>(ASN1::Type::SEQUENCE)},                       //    type: asn1.Type.SEQUENCE,
        {"constructed", true},                                                  //    constructed: true,
        {"value",                                                               //    value:
        juce::Array<juce::var>{//begin array                                    //    [
            createObject({//begin object                                        //        {
                // Version (INTEGER)                                            //            // Version (INTEGER)
                {"name", "RSAPrivateKey.version"},                              //            name: 'RSAPrivateKey.version',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyVersion"}                                //            capture: 'privateKeyVersion'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // modulus (n)                                                  //            // modulus (n)
                {"name", "RSAPrivateKey.modulus"},                              //            name: 'RSAPrivateKey.modulus',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyModulus"}                                //            capture: 'privateKeyModulus'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
         // publicExponent (e)                                                  //            // publicExponent (e)
                {"name", "RSAPrivateKey.publicExponent"},                       //            name: 'RSAPrivateKey.publicExponent',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyPublicExponent"}                         //            capture: 'privateKeyPublicExponent'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // privateExponent (d)                                          //            // privateExponent (d)
                {"name", "RSAPrivateKey.privateExponent"},                      //            name: 'RSAPrivateKey.privateExponent',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyPrivateExponent"}                        //            capture: 'privateKeyPrivateExponent'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // prime1 (p)                                                   //            // prime1 (p)
                {"name", "RSAPrivateKey.prime1"},                               //            name: 'RSAPrivateKey.prime1',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyPrime1"}                                 //            capture: 'privateKeyPrime1'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // prime2 (q)                                                   //            // prime2 (q)
                {"name", "RSAPrivateKey.prime2"},                               //            name: 'RSAPrivateKey.prime2',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyPrime2"}                                 //            capture: 'privateKeyPrime2'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // exponent1 (d mod (p-1))                                      //            // exponent1 (d mod (p-1))
                {"name", "RSAPrivateKey.exponent1"},                            //            name: 'RSAPrivateKey.exponent1',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyExponent1"}                              //            capture: 'privateKeyExponent1'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // exponent2 (d mod (q-1))                                      //            // exponent2 (d mod (q-1))
                {"name", "RSAPrivateKey.exponent2"},                            //            name: 'RSAPrivateKey.exponent2',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyExponent2"}                              //            capture: 'privateKeyExponent2'
            }),//end object                                                     //        },
            createObject({//begin object                                        //        {
                // coefficient ((inverse of q) mod p)                           //            // coefficient ((inverse of q) mod p)
                {"name", "RSAPrivateKey.coefficient"},                          //            name: 'RSAPrivateKey.coefficient',
                {"tagClass", static_cast<int>(ASN1::Class::UNIVERSAL)},         //            tagClass: asn1.Class.UNIVERSAL,
                {"type", static_cast<int>(ASN1::Type::INTEGER)},                //            type: asn1.Type.INTEGER,
                {"constructed", false},                                         //            constructed: false,
                {"capture", "privateKeyCoefficient"}                            //            capture: 'privateKeyCoefficient'
            })//end object                                                      //        }
        }}//end array                                                           //    ]
    });//end object                                                             //};
    
    return rsaPrivateKeyValidator;
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
