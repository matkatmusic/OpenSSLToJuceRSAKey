/*
  ==============================================================================

    Oids.cpp
    Created: 26 Jun 2022 11:01:27am
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#include "Oids.h"

const std::map<juce::String, juce::String>& Forge::oids()
{
    static std::map<juce::String, juce::String> map;
    
    auto _IN = [](juce::String id,
                  juce::String name,
                  std::map<juce::String, juce::String>& oids)
    {
        oids[id] = name;
        oids[name] = id;
    };
    
    auto _I_ = [](juce::String id,
                  juce::String name,
                  std::map<juce::String, juce::String>& oids)
    {
        oids[id] = name;
        oids[name] = "DEPRECATED";
    };
    
    auto construct = [&]()
    {
        // algorithm OIDs
        _IN("1.2.840.113549.1.1.1", "rsaEncryption", map);
        // Note: md2 & md4 not implemented
        //_IN("1.2.840.113549.1.1.2", "md2WithRSAEncryption", map);
        //_IN("1.2.840.113549.1.1.3", "md4WithRSAEncryption", map);
        _IN("1.2.840.113549.1.1.4", "md5WithRSAEncryption", map);
        _IN("1.2.840.113549.1.1.5", "sha1WithRSAEncryption", map);
        _IN("1.2.840.113549.1.1.7", "RSAES-OAEP", map);
        _IN("1.2.840.113549.1.1.8", "mgf1", map);
        _IN("1.2.840.113549.1.1.9", "pSpecified", map);
        _IN("1.2.840.113549.1.1.10", "RSASSA-PSS", map);
        _IN("1.2.840.113549.1.1.11", "sha256WithRSAEncryption", map);
        _IN("1.2.840.113549.1.1.12", "sha384WithRSAEncryption", map);
        _IN("1.2.840.113549.1.1.13", "sha512WithRSAEncryption", map);
        // Edwards-curve Digital Signature Algorithm (EdDSA) Ed25519
        _IN("1.3.101.112", "EdDSA25519", map);

        _IN("1.2.840.10040.4.3", "dsa-with-sha1", map);

        _IN("1.3.14.3.2.7", "desCBC", map);

        _IN("1.3.14.3.2.26", "sha1", map);
        // Deprecated equivalent of sha1WithRSAEncryption
        _IN("1.3.14.3.2.29", "sha1WithRSASignature", map);
        _IN("2.16.840.1.101.3.4.2.1", "sha256", map);
        _IN("2.16.840.1.101.3.4.2.2", "sha384", map);
        _IN("2.16.840.1.101.3.4.2.3", "sha512", map);
        _IN("2.16.840.1.101.3.4.2.4", "sha224", map);
        _IN("2.16.840.1.101.3.4.2.5", "sha512-224", map);
        _IN("2.16.840.1.101.3.4.2.6", "sha512-256", map);
        _IN("1.2.840.113549.2.2", "md2", map);
        _IN("1.2.840.113549.2.5", "md5", map);

        // pkcs#7 content types
        _IN("1.2.840.113549.1.7.1", "data", map);
        _IN("1.2.840.113549.1.7.2", "signedData", map);
        _IN("1.2.840.113549.1.7.3", "envelopedData", map);
        _IN("1.2.840.113549.1.7.4", "signedAndEnvelopedData", map);
        _IN("1.2.840.113549.1.7.5", "digestedData", map);
        _IN("1.2.840.113549.1.7.6", "encryptedData", map);

        // pkcs#9 oids
        _IN("1.2.840.113549.1.9.1", "emailAddress", map);
        _IN("1.2.840.113549.1.9.2", "unstructuredName", map);
        _IN("1.2.840.113549.1.9.3", "contentType", map);
        _IN("1.2.840.113549.1.9.4", "messageDigest", map);
        _IN("1.2.840.113549.1.9.5", "signingTime", map);
        _IN("1.2.840.113549.1.9.6", "counterSignature", map);
        _IN("1.2.840.113549.1.9.7", "challengePassword", map);
        _IN("1.2.840.113549.1.9.8", "unstructuredAddress", map);
        _IN("1.2.840.113549.1.9.14", "extensionRequest", map);

        _IN("1.2.840.113549.1.9.20", "friendlyName", map);
        _IN("1.2.840.113549.1.9.21", "localKeyId", map);
        _IN("1.2.840.113549.1.9.22.1", "x509Certificate", map);

        // pkcs#12 safe bags
        _IN("1.2.840.113549.1.12.10.1.1", "keyBag", map);
        _IN("1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag", map);
        _IN("1.2.840.113549.1.12.10.1.3", "certBag", map);
        _IN("1.2.840.113549.1.12.10.1.4", "crlBag", map);
        _IN("1.2.840.113549.1.12.10.1.5", "secretBag", map);
        _IN("1.2.840.113549.1.12.10.1.6", "safeContentsBag", map);

        // password-based-encryption for pkcs#12
        _IN("1.2.840.113549.1.5.13", "pkcs5PBES2", map);
        _IN("1.2.840.113549.1.5.12", "pkcs5PBKDF2", map);

        _IN("1.2.840.113549.1.12.1.1", "pbeWithSHAAnd128BitRC4", map);
        _IN("1.2.840.113549.1.12.1.2", "pbeWithSHAAnd40BitRC4", map);
        _IN("1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC", map);
        _IN("1.2.840.113549.1.12.1.4", "pbeWithSHAAnd2-KeyTripleDES-CBC", map);
        _IN("1.2.840.113549.1.12.1.5", "pbeWithSHAAnd128BitRC2-CBC", map);
        _IN("1.2.840.113549.1.12.1.6", "pbewithSHAAnd40BitRC2-CBC", map);

        // hmac OIDs
        _IN("1.2.840.113549.2.7", "hmacWithSHA1", map);
        _IN("1.2.840.113549.2.8", "hmacWithSHA224", map);
        _IN("1.2.840.113549.2.9", "hmacWithSHA256", map);
        _IN("1.2.840.113549.2.10", "hmacWithSHA384", map);
        _IN("1.2.840.113549.2.11", "hmacWithSHA512", map);

        // symmetric key algorithm oids
        _IN("1.2.840.113549.3.7", "des-EDE3-CBC", map);
        _IN("2.16.840.1.101.3.4.1.2", "aes128-CBC", map);
        _IN("2.16.840.1.101.3.4.1.22", "aes192-CBC", map);
        _IN("2.16.840.1.101.3.4.1.42", "aes256-CBC", map);

        // certificate issuer/subject OIDs
        _IN("2.5.4.3", "commonName", map);
        _IN("2.5.4.4", "surname", map);
        _IN("2.5.4.5", "serialNumber", map);
        _IN("2.5.4.6", "countryName", map);
        _IN("2.5.4.7", "localityName", map);
        _IN("2.5.4.8", "stateOrProvinceName", map);
        _IN("2.5.4.9", "streetAddress", map);
        _IN("2.5.4.10", "organizationName", map);
        _IN("2.5.4.11", "organizationalUnitName", map);
        _IN("2.5.4.12", "title", map);
        _IN("2.5.4.13", "description", map);
        _IN("2.5.4.15", "businessCategory", map);
        _IN("2.5.4.17", "postalCode", map);
        _IN("2.5.4.42", "givenName", map);
        _IN("1.3.6.1.4.1.311.60.2.1.2", "jurisdictionOfIncorporationStateOrProvinceName", map);
        _IN("1.3.6.1.4.1.311.60.2.1.3", "jurisdictionOfIncorporationCountryName", map);

        // X.509 extension OIDs
        _IN("2.16.840.1.113730.1.1", "nsCertType", map);
        _IN("2.16.840.1.113730.1.13", "nsComment", map); // deprecated in theory; still widely used
        _I_("2.5.29.1", "authorityKeyIdentifier", map); // deprecated, use .35
        _I_("2.5.29.2", "keyAttributes", map); // obsolete use .37 or .15
        _I_("2.5.29.3", "certificatePolicies", map); // deprecated, use .32
        _I_("2.5.29.4", "keyUsageRestriction", map); // obsolete use .37 or .15
        _I_("2.5.29.5", "policyMapping", map); // deprecated use .33
        _I_("2.5.29.6", "subtreesConstraint", map); // obsolete use .30
        _I_("2.5.29.7", "subjectAltName", map); // deprecated use .17
        _I_("2.5.29.8", "issuerAltName", map); // deprecated use .18
        _I_("2.5.29.9", "subjectDirectoryAttributes", map);
        _I_("2.5.29.10", "basicConstraints", map); // deprecated use .19
        _I_("2.5.29.11", "nameConstraints", map); // deprecated use .30
        _I_("2.5.29.12", "policyConstraints", map); // deprecated use .36
        _I_("2.5.29.13", "basicConstraints", map); // deprecated use .19
        _IN("2.5.29.14", "subjectKeyIdentifier", map);
        _IN("2.5.29.15", "keyUsage", map);
        _I_("2.5.29.16", "privateKeyUsagePeriod", map);
        _IN("2.5.29.17", "subjectAltName", map);
        _IN("2.5.29.18", "issuerAltName", map);
        _IN("2.5.29.19", "basicConstraints", map);
        _I_("2.5.29.20", "cRLNumber", map);
        _I_("2.5.29.21", "cRLReason", map);
        _I_("2.5.29.22", "expirationDate", map);
        _I_("2.5.29.23", "instructionCode", map);
        _I_("2.5.29.24", "invalidityDate", map);
        _I_("2.5.29.25", "cRLDistributionPoints", map); // deprecated use .31
        _I_("2.5.29.26", "issuingDistributionPoint", map); // deprecated use .28
        _I_("2.5.29.27", "deltaCRLIndicator", map);
        _I_("2.5.29.28", "issuingDistributionPoint", map);
        _I_("2.5.29.29", "certificateIssuer", map);
        _I_("2.5.29.30", "nameConstraints", map);
        _IN("2.5.29.31", "cRLDistributionPoints", map);
        _IN("2.5.29.32", "certificatePolicies", map);
        _I_("2.5.29.33", "policyMappings", map);
        _I_("2.5.29.34", "policyConstraints", map); // deprecated use .36
        _IN("2.5.29.35", "authorityKeyIdentifier", map);
        _I_("2.5.29.36", "policyConstraints", map);
        _IN("2.5.29.37", "extKeyUsage", map);
        _I_("2.5.29.46", "freshestCRL", map);
        _I_("2.5.29.54", "inhibitAnyPolicy", map);

        // extKeyUsage purposes
        _IN("1.3.6.1.4.1.11129.2.4.2", "timestampList", map);
        _IN("1.3.6.1.5.5.7.1.1", "authorityInfoAccess", map);
        _IN("1.3.6.1.5.5.7.3.1", "serverAuth", map);
        _IN("1.3.6.1.5.5.7.3.2", "clientAuth", map);
        _IN("1.3.6.1.5.5.7.3.3", "codeSigning", map);
        _IN("1.3.6.1.5.5.7.3.4", "emailProtection", map);
        _IN("1.3.6.1.5.5.7.3.8", "timeStamping", map);
    };

    if( map.empty() )
        construct();
    
    return map;
}
