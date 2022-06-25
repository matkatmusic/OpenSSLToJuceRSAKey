# OpenSSLToJuceRSAKey
a collection of classes that convert OpenSSL-generated X509 Public and Private keys into the juce::RSAKey format

usage: 
```
juce::String key ( "------ BEGIN PUBLIC KEY------" .... );
juce::String expected ("this is a test message");
juce::String encrypted( "encrypted Base64 message goes here" );

PEMFormatKey rsaKey;
rsaKey.loadFromPEMFormattedString(key);
jassert(rsaKey.isValid());

auto decryptedString = rsaKey.decryptBase64String(encrypted);
jassert( decryptedString == expected );
```
