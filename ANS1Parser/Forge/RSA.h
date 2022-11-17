/*
  ==============================================================================

    RSA.h
    Created: 15 Jul 2022 4:02:48pm
    Author:  Matkat Music LLC

  ==============================================================================
*/

#pragma once

#include <JuceHeader.h>

/*
 a port of https://github.com/digitalbazaar/forge/blob/main/lib/rsa.js
 */
#include "ASN1.h"
#include "Oids.h"

namespace Forge
{
namespace PKI
{
namespace V1
{
juce::String findOID(juce::String oidToFind);
} //end namespace V1
namespace V2
{
juce::MemoryBlock _bnToBytes(const juce::BigInteger& b);
} //end namespace V2
} //end namespace PKI
} //end namespace Forge
#if false
/**
 * Javascript implementation of basic RSA algorithms.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 *
 * The only algorithm currently supported for PKI is RSA.
 *
 * An RSA key is often stored in ASN.1 DER format. The SubjectPublicKeyInfo
 * ASN.1 structure is composed of an algorithm of type AlgorithmIdentifier
 * and a subjectPublicKey of type bit string.
 *
 * The AlgorithmIdentifier contains an Object Identifier (OID) and parameters
 * for the algorithm, if any. In the case of RSA, there aren't any.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 *
 * AlgorithmIdentifer ::= SEQUENCE {
 *   algorithm OBJECT IDENTIFIER,
 *   parameters ANY DEFINED BY algorithm OPTIONAL
 * }
 *
 * For an RSA public key, the subjectPublicKey is:
 *
 * RSAPublicKey ::= SEQUENCE {
 *   modulus            INTEGER,    -- n
 *   publicExponent     INTEGER     -- e
 * }
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                   Version,
 *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *   privateKey                PrivateKey,
 *   attributes           [0]  IMPLICIT Attributes OPTIONAL
 * }
 *
 * Version ::= INTEGER
 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 * PrivateKey ::= OCTET STRING
 * Attributes ::= SET OF Attribute
 *
 * An RSA private key as the following structure:
 *
 * RSAPrivateKey ::= SEQUENCE {
 *   version Version,
 *   modulus INTEGER, -- n
 *   publicExponent INTEGER, -- e
 *   privateExponent INTEGER, -- d
 *   prime1 INTEGER, -- p
 *   prime2 INTEGER, -- q
 *   exponent1 INTEGER, -- d mod (p-1)
 *   exponent2 INTEGER, -- d mod (q-1)
 *   coefficient INTEGER -- (inverse of q) mod p
 * }
 *
 * Version ::= INTEGER
 *
 * The OID for the RSA key algorithm is: 1.2.840.113549.1.1.1
 */
var forge = require('./forge');
require('./asn1');
require('./jsbn');
require('./oids');
require('./pkcs1');
require('./prime');
require('./random');
require('./util');

if(typeof BigInteger === 'undefined') {
  var BigInteger = forge.jsbn.BigInteger;
}

var _crypto = forge.util.isNodejs ? require('crypto') : null;

// shortcut for asn.1 API
var asn1 = forge.asn1;

// shortcut for util API
var util = forge.util;

/*
 * RSA encryption and decryption, see RFC 2313.
 */
forge.pki = forge.pki || {};
module.exports = forge.pki.rsa = forge.rsa = forge.rsa || {};
var pki = forge.pki;

// for finding primes, which are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
var GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];

// validator for a PrivateKeyInfo structure
var privateKeyValidator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'PrivateKeyInfo.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion'
  }, {
    // privateKeyAlgorithm
    name: 'PrivateKeyInfo.privateKeyAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'privateKeyOid'
    }]
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'privateKey'
  }]
};

// validator for an RSA private key
var rsaPrivateKeyValidator = {
  // RSAPrivateKey
  name: 'RSAPrivateKey',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'RSAPrivateKey.version',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion'
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyModulus'
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPublicExponent'
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrivateExponent'
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime1'
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime2'
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent1'
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent2'
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.INTEGER,
    constructed: false,
    capture: 'privateKeyCoefficient'
  }]
};
#endif
// validator for an SubjectPublicKeyInfo structure
// Note: Currently only works with an RSA public key
namespace Forge
{
namespace RSA
{
namespace V1
{
/*
 TODO: use the juce::var class to replace a lot of these named variables
 why?
 juce::var has operator[](const Identifier&), which returns a var.
 
 var can store:
     int
     int64
     double
     bool
     array<var>
     memoryBlock
     String
     ReferenceCountedObject's 
 */
struct Validator : juce::ReferenceCountedObject
{
    using Ptr = juce::ReferenceCountedObjectPtr<Validator>;
    
    juce::String name;
    Forge::ASN1::Class tagClass;
    Forge::ASN1::Type type;
    bool constructed = false;
    bool optional = false;
    bool captureBitStringContents = false;
    bool captureBitStringValue = false;
    juce::String captureAsn1;
    juce::String capture;
    std::vector<Ptr> value;
//
//    Validator(juce::String name_,
//              Forge::ASN1::Class tagClass_,
//              Forge::ASN1::Type type_,
//              bool constructed_,
//              bool optional_ = false,
//              juce::String captureAsn1_ = {},
//              std::vector<Ptr> value_ = {}) :
//    name(name_),
//    tagClass(tagClass_),
//    type(type_),
//    constructed(constructed_),
//    optional(optional_),
//    captureAsn1(captureAsn1_),
//    value(value_)
//    {
//    }
};
// validator for an RSA public key
Validator::Ptr getRSAPublicKeyValidator();


//var publicKeyValidator = forge.pki.rsa.publicKeyValidator = {
Validator::Ptr getPublicKeyValidator();
} //end namespace V1
namespace V2
{
juce::var getPublicKeyValidator();
juce::var getRSAPublicKeyValidator();
juce::var getPrivateKeyValidator();
juce::var getRsaPrivateKeyValidator();
} //end namespace V2
} //end namespace RSA
} //end namespace Forge
#if false
// validator for a DigestInfo structure
var digestInfoValidator = {
  name: 'DigestInfo',
  tagClass: asn1.Class.UNIVERSAL,
  type: asn1.Type.SEQUENCE,
  constructed: true,
  value: [{
    name: 'DigestInfo.DigestAlgorithm',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'DigestInfo.DigestAlgorithm.algorithmIdentifier',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.OID,
      constructed: false,
      capture: 'algorithmIdentifier'
    }, {
      // NULL paramters
      name: 'DigestInfo.DigestAlgorithm.parameters',
      tagClass: asn1.Class.UNIVERSAL,
      type: asn1.Type.NULL,
      // captured only to check existence for md2 and md5
      capture: 'parameters',
      optional: true,
      constructed: false
    }]
  }, {
    // digest
    name: 'DigestInfo.digest',
    tagClass: asn1.Class.UNIVERSAL,
    type: asn1.Type.OCTETSTRING,
    constructed: false,
    capture: 'digest'
  }]
};

/**
 * Wrap digest in DigestInfo object.
 *
 * This function implements EMSA-PKCS1-v1_5-ENCODE as per RFC 3447.
 *
 * DigestInfo ::= SEQUENCE {
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   digest Digest
 * }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * Digest ::= OCTET STRING
 *
 * @param md the message digest object with the hash to sign.
 *
 * @return the encoded message (ready for RSA encrytion)
 */
var emsaPkcs1v15encode = function(md) {
  // get the oid for the algorithm
  var oid;
  if(md.algorithm in pki.oids) {
    oid = pki.oids[md.algorithm];
  } else {
    var error = new Error('Unknown message digest algorithm.');
    error.algorithm = md.algorithm;
    throw error;
  }
  var oidBytes = asn1.oidToDer(oid).getBytes();

  // create the digest info
  var digestInfo = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  var digestAlgorithm = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, []);
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.OID, false, oidBytes));
  digestAlgorithm.value.push(asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''));
  var digest = asn1.create(
    asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING,
    false, md.digest().getBytes());
  digestInfo.value.push(digestAlgorithm);
  digestInfo.value.push(digest);

  // encode digest info
  return asn1.toDer(digestInfo).getBytes();
};

/**
 * Performs x^c mod n (RSA encryption or decryption operation).
 *
 * @param x the number to raise and mod.
 * @param key the key to use.
 * @param pub true if the key is public, false if private.
 *
 * @return the result of x^c mod n.
 */
var _modPow = function(x, key, pub) {
  if(pub) {
    return x.modPow(key.e, key.n);
  }

  if(!key.p || !key.q) {
    // allow calculation without CRT params (slow)
    return x.modPow(key.d, key.n);
  }

  // pre-compute dP, dQ, and qInv if necessary
  if(!key.dP) {
    key.dP = key.d.mod(key.p.subtract(BigInteger.ONE));
  }
  if(!key.dQ) {
    key.dQ = key.d.mod(key.q.subtract(BigInteger.ONE));
  }
  if(!key.qInv) {
    key.qInv = key.q.modInverse(key.p);
  }

  /* Chinese remainder theorem (CRT) states:

    Suppose n1, n2, ..., nk are positive integers which are pairwise
    coprime (n1 and n2 have no common factors other than 1). For any
    integers x1, x2, ..., xk there exists an integer x solving the
    system of simultaneous congruences (where ~= means modularly
    congruent so a ~= b mod n means a mod n = b mod n):

    x ~= x1 mod n1
    x ~= x2 mod n2
    ...
    x ~= xk mod nk

    This system of congruences has a single simultaneous solution x
    between 0 and n - 1. Furthermore, each xk solution and x itself
    is congruent modulo the product n = n1*n2*...*nk.
    So x1 mod n = x2 mod n = xk mod n = x mod n.

    The single simultaneous solution x can be solved with the following
    equation:

    x = sum(xi*ri*si) mod n where ri = n/ni and si = ri^-1 mod ni.

    Where x is less than n, xi = x mod ni.

    For RSA we are only concerned with k = 2. The modulus n = pq, where
    p and q are coprime. The RSA decryption algorithm is:

    y = x^d mod n

    Given the above:

    x1 = x^d mod p
    r1 = n/p = q
    s1 = q^-1 mod p
    x2 = x^d mod q
    r2 = n/q = p
    s2 = p^-1 mod q

    So y = (x1r1s1 + x2r2s2) mod n
         = ((x^d mod p)q(q^-1 mod p) + (x^d mod q)p(p^-1 mod q)) mod n

    According to Fermat's Little Theorem, if the modulus P is prime,
    for any integer A not evenly divisible by P, A^(P-1) ~= 1 mod P.
    Since A is not divisible by P it follows that if:
    N ~= M mod (P - 1), then A^N mod P = A^M mod P. Therefore:

    A^N mod P = A^(M mod (P - 1)) mod P. (The latter takes less effort
    to calculate). In order to calculate x^d mod p more quickly the
    exponent d mod (p - 1) is stored in the RSA private key (the same
    is done for x^d mod q). These values are referred to as dP and dQ
    respectively. Therefore we now have:

    y = ((x^dP mod p)q(q^-1 mod p) + (x^dQ mod q)p(p^-1 mod q)) mod n

    Since we'll be reducing x^dP by modulo p (same for q) we can also
    reduce x by p (and q respectively) before hand. Therefore, let

    xp = ((x mod p)^dP mod p), and
    xq = ((x mod q)^dQ mod q), yielding:

    y = (xp*q*(q^-1 mod p) + xq*p*(p^-1 mod q)) mod n

    This can be further reduced to a simple algorithm that only
    requires 1 inverse (the q inverse is used) to be used and stored.
    The algorithm is called Garner's algorithm. If qInv is the
    inverse of q, we simply calculate:

    y = (qInv*(xp - xq) mod p) * q + xq

    However, there are two further complications. First, we need to
    ensure that xp > xq to prevent signed BigIntegers from being used
    so we add p until this is true (since we will be mod'ing with
    p anyway). Then, there is a known timing attack on algorithms
    using the CRT. To mitigate this risk, "cryptographic blinding"
    should be used. This requires simply generating a random number r
    between 0 and n-1 and its inverse and multiplying x by r^e before
    calculating y and then multiplying y by r^-1 afterwards. Note that
    r must be coprime with n (gcd(r, n) === 1) in order to have an
    inverse.
  */

  // cryptographic blinding
  var r;
  do {
    r = new BigInteger(
      forge.util.bytesToHex(forge.random.getBytes(key.n.bitLength() / 8)),
      16);
  } while(r.compareTo(key.n) >= 0 || !r.gcd(key.n).equals(BigInteger.ONE));
  x = x.multiply(r.modPow(key.e, key.n)).mod(key.n);

  // calculate xp and xq
  var xp = x.mod(key.p).modPow(key.dP, key.p);
  var xq = x.mod(key.q).modPow(key.dQ, key.q);

  // xp must be larger than xq to avoid signed bit usage
  while(xp.compareTo(xq) < 0) {
    xp = xp.add(key.p);
  }

  // do last step
  var y = xp.subtract(xq)
    .multiply(key.qInv).mod(key.p)
    .multiply(key.q).add(xq);

  // remove effect of random for cryptographic blinding
  y = y.multiply(r.modInverse(key.n)).mod(key.n);

  return y;
};

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'sign' on a private key object or
 * 'encrypt' on a public key object instead.
 *
 * Performs RSA encryption.
 *
 * The parameter bt controls whether to put padding bytes before the
 * message passed in. Set bt to either true or false to disable padding
 * completely (in order to handle e.g. EMSA-PSS encoding seperately before),
 * signaling whether the encryption operation is a public key operation
 * (i.e. encrypting data) or not, i.e. private key operation (data signing).
 *
 * For PKCS#1 v1.5 padding pass in the block type to use, i.e. either 0x01
 * (for signing) or 0x02 (for encryption). The key operation mode (private
 * or public) is derived from this flag in that case).
 *
 * @param m the message to encrypt as a byte string.
 * @param key the RSA key to use.
 * @param bt for PKCS#1 v1.5 padding, the block type to use
 *   (0x01 for private key, 0x02 for public),
 *   to disable padding: true = public key, false = private key.
 *
 * @return the encrypted bytes as a string.
 */
pki.rsa.encrypt = function(m, key, bt) {
  var pub = bt;
  var eb;

  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  if(bt !== false && bt !== true) {
    // legacy, default to PKCS#1 v1.5 padding
    pub = (bt === 0x02);
    eb = _encodePkcs1_v1_5(m, key, bt);
  } else {
    eb = forge.util.createBuffer();
    eb.putBytes(m);
  }

  // load encryption block as big integer 'x'
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var x = new BigInteger(eb.toHex(), 16);

  // do RSA encryption
  var y = _modPow(x, key, pub);

  // convert y into the encrypted data byte string, if y is shorter in
  // bytes than k, then prepend zero bytes to fill up ed
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var yhex = y.toString(16);
  var ed = forge.util.createBuffer();
  var zeros = k - Math.ceil(yhex.length / 2);
  while(zeros > 0) {
    ed.putByte(0x00);
    --zeros;
  }
  ed.putBytes(forge.util.hexToBytes(yhex));
  return ed.getBytes();
};

/**
 * NOTE: THIS METHOD IS DEPRECATED, use 'decrypt' on a private key object or
 * 'verify' on a public key object instead.
 *
 * Performs RSA decryption.
 *
 * The parameter ml controls whether to apply PKCS#1 v1.5 padding
 * or not.  Set ml = false to disable padding removal completely
 * (in order to handle e.g. EMSA-PSS later on) and simply pass back
 * the RSA encryption block.
 *
 * @param ed the encrypted data to decrypt in as a byte string.
 * @param key the RSA key to use.
 * @param pub true for a public key operation, false for private.
 * @param ml the message length, if known, false to disable padding.
 *
 * @return the decrypted message as a byte string.
 */
pki.rsa.decrypt = function(ed, key, pub, ml) {
  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  // error if the length of the encrypted data ED is not k
  if(ed.length !== k) {
    var error = new Error('Encrypted message length is invalid.');
    error.length = ed.length;
    error.expected = k;
    throw error;
  }

  // convert encrypted data into a big integer
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var y = new BigInteger(forge.util.createBuffer(ed).toHex(), 16);

  // y must be less than the modulus or it wasn't the result of
  // a previous mod operation (encryption) using that modulus
  if(y.compareTo(key.n) >= 0) {
    throw new Error('Encrypted message is invalid.');
  }

  // do RSA decryption
  var x = _modPow(y, key, pub);

  // create the encryption block, if x is shorter in bytes than k, then
  // prepend zero bytes to fill up eb
  // FIXME: hex conversion inefficient, get BigInteger w/byte strings
  var xhex = x.toString(16);
  var eb = forge.util.createBuffer();
  var zeros = k - Math.ceil(xhex.length / 2);
  while(zeros > 0) {
    eb.putByte(0x00);
    --zeros;
  }
  eb.putBytes(forge.util.hexToBytes(xhex));

  if(ml !== false) {
    // legacy, default to PKCS#1 v1.5 padding
    return _decodePkcs1_v1_5(eb.getBytes(), key, pub);
  }

  // return message
  return eb.getBytes();
};

/**
 * Creates an RSA key-pair generation state object. It is used to allow
 * key-generation to be performed in steps. It also allows for a UI to
 * display progress updates.
 *
 * @param bits the size for the private key in bits, defaults to 2048.
 * @param e the public exponent to use, defaults to 65537 (0x10001).
 * @param [options] the options to use.
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync".
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 *
 * @return the state object to use to generate the key-pair.
 */
pki.rsa.createKeyPairGenerationState = function(bits, e, options) {
  // TODO: migrate step-based prime generation code to forge.prime

  // set default bits
  if(typeof(bits) === 'string') {
    bits = parseInt(bits, 10);
  }
  bits = bits || 2048;

  // create prng with api that matches BigInteger secure random
  options = options || {};
  var prng = options.prng || forge.random;
  var rng = {
    // x is an array to fill with bytes
    nextBytes: function(x) {
      var b = prng.getBytesSync(x.length);
      for(var i = 0; i < x.length; ++i) {
        x[i] = b.charCodeAt(i);
      }
    }
  };

  var algorithm = options.algorithm || 'PRIMEINC';

  // create PRIMEINC algorithm state
  var rval;
  if(algorithm === 'PRIMEINC') {
    rval = {
      algorithm: algorithm,
      state: 0,
      bits: bits,
      rng: rng,
      eInt: e || 65537,
      e: new BigInteger(null),
      p: null,
      q: null,
      qBits: bits >> 1,
      pBits: bits - (bits >> 1),
      pqState: 0,
      num: null,
      keys: null
    };
    rval.e.fromInt(rval.eInt);
  } else {
    throw new Error('Invalid key generation algorithm: ' + algorithm);
  }

  return rval;
};

/**
 * Attempts to runs the key-generation algorithm for at most n seconds
 * (approximately) using the given state. When key-generation has completed,
 * the keys will be stored in state.keys.
 *
 * To use this function to update a UI while generating a key or to prevent
 * causing browser lockups/warnings, set "n" to a value other than 0. A
 * simple pattern for generating a key and showing a progress indicator is:
 *
 * var state = pki.rsa.createKeyPairGenerationState(2048);
 * var step = function() {
 *   // step key-generation, run algorithm for 100 ms, repeat
 *   if(!forge.pki.rsa.stepKeyPairGenerationState(state, 100)) {
 *     setTimeout(step, 1);
 *   } else {
 *     // key-generation complete
 *     // TODO: turn off progress indicator here
 *     // TODO: use the generated key-pair in "state.keys"
 *   }
 * };
 * // TODO: turn on progress indicator here
 * setTimeout(step, 0);
 *
 * @param state the state to use.
 * @param n the maximum number of milliseconds to run the algorithm for, 0
 *          to run the algorithm to completion.
 *
 * @return true if the key-generation completed, false if not.
 */
pki.rsa.stepKeyPairGenerationState = function(state, n) {
  // set default algorithm if not set
  if(!('algorithm' in state)) {
    state.algorithm = 'PRIMEINC';
  }

  // TODO: migrate step-based prime generation code to forge.prime
  // TODO: abstract as PRIMEINC algorithm

  // do key generation (based on Tom Wu's rsa.js, see jsbn.js license)
  // with some minor optimizations and designed to run in steps

  // local state vars
  var THIRTY = new BigInteger(null);
  THIRTY.fromInt(30);
  var deltaIdx = 0;
  var op_or = function(x, y) {return x | y;};

  // keep stepping until time limit is reached or done
  var t1 = +new Date();
  var t2;
  var total = 0;
  while(state.keys === null && (n <= 0 || total < n)) {
    // generate p or q
    if(state.state === 0) {
      /* Note: All primes are of the form:

        30k+i, for i < 30 and gcd(30, i)=1, where there are 8 values for i

        When we generate a random number, we always align it at 30k + 1. Each
        time the number is determined not to be prime we add to get to the
        next 'i', eg: if the number was at 30k + 1 we add 6. */
      var bits = (state.p === null) ? state.pBits : state.qBits;
      var bits1 = bits - 1;

      // get a random number
      if(state.pqState === 0) {
        state.num = new BigInteger(bits, state.rng);
        // force MSB set
        if(!state.num.testBit(bits1)) {
          state.num.bitwiseTo(
            BigInteger.ONE.shiftLeft(bits1), op_or, state.num);
        }
        // align number on 30k+1 boundary
        state.num.dAddOffset(31 - state.num.mod(THIRTY).byteValue(), 0);
        deltaIdx = 0;

        ++state.pqState;
      } else if(state.pqState === 1) {
        // try to make the number a prime
        if(state.num.bitLength() > bits) {
          // overflow, try again
          state.pqState = 0;
          // do primality test
        } else if(state.num.isProbablePrime(
          _getMillerRabinTests(state.num.bitLength()))) {
          ++state.pqState;
        } else {
          // get next potential prime
          state.num.dAddOffset(GCD_30_DELTA[deltaIdx++ % 8], 0);
        }
      } else if(state.pqState === 2) {
        // ensure number is coprime with e
        state.pqState =
          (state.num.subtract(BigInteger.ONE).gcd(state.e)
            .compareTo(BigInteger.ONE) === 0) ? 3 : 0;
      } else if(state.pqState === 3) {
        // store p or q
        state.pqState = 0;
        if(state.p === null) {
          state.p = state.num;
        } else {
          state.q = state.num;
        }

        // advance state if both p and q are ready
        if(state.p !== null && state.q !== null) {
          ++state.state;
        }
        state.num = null;
      }
    } else if(state.state === 1) {
      // ensure p is larger than q (swap them if not)
      if(state.p.compareTo(state.q) < 0) {
        state.num = state.p;
        state.p = state.q;
        state.q = state.num;
      }
      ++state.state;
    } else if(state.state === 2) {
      // compute phi: (p - 1)(q - 1) (Euler's totient function)
      state.p1 = state.p.subtract(BigInteger.ONE);
      state.q1 = state.q.subtract(BigInteger.ONE);
      state.phi = state.p1.multiply(state.q1);
      ++state.state;
    } else if(state.state === 3) {
      // ensure e and phi are coprime
      if(state.phi.gcd(state.e).compareTo(BigInteger.ONE) === 0) {
        // phi and e are coprime, advance
        ++state.state;
      } else {
        // phi and e aren't coprime, so generate a new p and q
        state.p = null;
        state.q = null;
        state.state = 0;
      }
    } else if(state.state === 4) {
      // create n, ensure n is has the right number of bits
      state.n = state.p.multiply(state.q);

      // ensure n is right number of bits
      if(state.n.bitLength() === state.bits) {
        // success, advance
        ++state.state;
      } else {
        // failed, get new q
        state.q = null;
        state.state = 0;
      }
    } else if(state.state === 5) {
      // set keys
      var d = state.e.modInverse(state.phi);
      state.keys = {
        privateKey: pki.rsa.setPrivateKey(
          state.n, state.e, d, state.p, state.q,
          d.mod(state.p1), d.mod(state.q1),
          state.q.modInverse(state.p)),
        publicKey: pki.rsa.setPublicKey(state.n, state.e)
      };
    }

    // update timing
    t2 = +new Date();
    total += t2 - t1;
    t1 = t2;
  }

  return state.keys !== null;
};

/**
 * Generates an RSA public-private key pair in a single call.
 *
 * To generate a key-pair in steps (to allow for progress updates and to
 * prevent blocking or warnings in slow browsers) then use the key-pair
 * generation state functions.
 *
 * To generate a key-pair asynchronously (either through web-workers, if
 * available, or by breaking up the work on the main thread), pass a
 * callback function.
 *
 * @param [bits] the size for the private key in bits, defaults to 2048.
 * @param [e] the public exponent to use, defaults to 65537.
 * @param [options] options for key-pair generation, if given then 'bits'
 *            and 'e' must *not* be given:
 *          bits the size for the private key in bits, (default: 2048).
 *          e the public exponent to use, (default: 65537 (0x10001)).
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 *          prng a custom crypto-secure pseudo-random number generator to use,
 *            that must define "getBytesSync". Disables use of native APIs.
 *          algorithm the algorithm to use (default: 'PRIMEINC').
 * @param [callback(err, keypair)] called once the operation completes.
 *
 * @return an object with privateKey and publicKey properties.
 */
pki.rsa.generateKeyPair = function(bits, e, options, callback) {
  // (bits), (options), (callback)
  if(arguments.length === 1) {
    if(typeof bits === 'object') {
      options = bits;
      bits = undefined;
    } else if(typeof bits === 'function') {
      callback = bits;
      bits = undefined;
    }
  } else if(arguments.length === 2) {
    // (bits, e), (bits, options), (bits, callback), (options, callback)
    if(typeof bits === 'number') {
      if(typeof e === 'function') {
        callback = e;
        e = undefined;
      } else if(typeof e !== 'number') {
        options = e;
        e = undefined;
      }
    } else {
      options = bits;
      callback = e;
      bits = undefined;
      e = undefined;
    }
  } else if(arguments.length === 3) {
    // (bits, e, options), (bits, e, callback), (bits, options, callback)
    if(typeof e === 'number') {
      if(typeof options === 'function') {
        callback = options;
        options = undefined;
      }
    } else {
      callback = options;
      options = e;
      e = undefined;
    }
  }
  options = options || {};
  if(bits === undefined) {
    bits = options.bits || 2048;
  }
  if(e === undefined) {
    e = options.e || 0x10001;
  }

  // use native code if permitted, available, and parameters are acceptable
  if(!forge.options.usePureJavaScript && !options.prng &&
    bits >= 256 && bits <= 16384 && (e === 0x10001 || e === 3)) {
    if(callback) {
      // try native async
      if(_detectNodeCrypto('generateKeyPair')) {
        return _crypto.generateKeyPair('rsa', {
          modulusLength: bits,
          publicExponent: e,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        }, function(err, pub, priv) {
          if(err) {
            return callback(err);
          }
          callback(null, {
            privateKey: pki.privateKeyFromPem(priv),
            publicKey: pki.publicKeyFromPem(pub)
          });
        });
      }
      if(_detectSubtleCrypto('generateKey') &&
        _detectSubtleCrypto('exportKey')) {
        // use standard native generateKey
        return util.globalScope.crypto.subtle.generateKey({
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: bits,
          publicExponent: _intToUint8Array(e),
          hash: {name: 'SHA-256'}
        }, true /* key can be exported*/, ['sign', 'verify'])
        .then(function(pair) {
          return util.globalScope.crypto.subtle.exportKey(
            'pkcs8', pair.privateKey);
        // avoiding catch(function(err) {...}) to support IE <= 8
        }).then(undefined, function(err) {
          callback(err);
        }).then(function(pkcs8) {
          if(pkcs8) {
            var privateKey = pki.privateKeyFromAsn1(
              asn1.fromDer(forge.util.createBuffer(pkcs8)));
            callback(null, {
              privateKey: privateKey,
              publicKey: pki.setRsaPublicKey(privateKey.n, privateKey.e)
            });
          }
        });
      }
      if(_detectSubtleMsCrypto('generateKey') &&
        _detectSubtleMsCrypto('exportKey')) {
        var genOp = util.globalScope.msCrypto.subtle.generateKey({
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: bits,
          publicExponent: _intToUint8Array(e),
          hash: {name: 'SHA-256'}
        }, true /* key can be exported*/, ['sign', 'verify']);
        genOp.oncomplete = function(e) {
          var pair = e.target.result;
          var exportOp = util.globalScope.msCrypto.subtle.exportKey(
            'pkcs8', pair.privateKey);
          exportOp.oncomplete = function(e) {
            var pkcs8 = e.target.result;
            var privateKey = pki.privateKeyFromAsn1(
              asn1.fromDer(forge.util.createBuffer(pkcs8)));
            callback(null, {
              privateKey: privateKey,
              publicKey: pki.setRsaPublicKey(privateKey.n, privateKey.e)
            });
          };
          exportOp.onerror = function(err) {
            callback(err);
          };
        };
        genOp.onerror = function(err) {
          callback(err);
        };
        return;
      }
    } else {
      // try native sync
      if(_detectNodeCrypto('generateKeyPairSync')) {
        var keypair = _crypto.generateKeyPairSync('rsa', {
          modulusLength: bits,
          publicExponent: e,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        });
        return {
          privateKey: pki.privateKeyFromPem(keypair.privateKey),
          publicKey: pki.publicKeyFromPem(keypair.publicKey)
        };
      }
    }
  }

  // use JavaScript implementation
  var state = pki.rsa.createKeyPairGenerationState(bits, e, options);
  if(!callback) {
    pki.rsa.stepKeyPairGenerationState(state, 0);
    return state.keys;
  }
  _generateKeyPair(state, options, callback);
};

/**
 * Sets an RSA public key from BigIntegers modulus and exponent.
 *
 * @param n the modulus.
 * @param e the exponent.
 *
 * @return the public key.
 */
pki.setRsaPublicKey = pki.rsa.setPublicKey = function(n, e) {
  var key = {
    n: n,
    e: e
  };

  /**
   * Encrypts the given data with this public key. Newer applications
   * should use the 'RSA-OAEP' decryption scheme, 'RSAES-PKCS1-V1_5' is for
   * legacy applications.
   *
   * @param data the byte string to encrypt.
   * @param scheme the encryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA encryption,
   *          an object with an 'encode' property set to a function
   *          with the signature 'function(data, key)' that returns
   *          a binary-encoded string representing the encoded data.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the encrypted byte string.
   */
  key.encrypt = function(data, scheme, schemeOptions) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5';
    }

    if(scheme === 'RSAES-PKCS1-V1_5') {
      scheme = {
        encode: function(m, key, pub) {
          return _encodePkcs1_v1_5(m, key, 0x02).getBytes();
        }
      };
    } else if(scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        encode: function(m, key) {
          return forge.pkcs1.encode_rsa_oaep(key, m, schemeOptions);
        }
      };
    } else if(['RAW', 'NONE', 'NULL', null].indexOf(scheme) !== -1) {
      scheme = {encode: function(e) {return e;}};
    } else if(typeof scheme === 'string') {
      throw new Error('Unsupported encryption scheme: "' + scheme + '".');
    }

    // do scheme-based encoding then rsa encryption
    var e = scheme.encode(data, key, true);
    return pki.rsa.encrypt(e, key, true);
  };

  /**
   * Verifies the given signature against the given digest.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5, in which case once RSA-decrypted, the
   * signature is an OCTET STRING that holds a DigestInfo.
   *
   * DigestInfo ::= SEQUENCE {
   *   digestAlgorithm DigestAlgorithmIdentifier,
   *   digest Digest
   * }
   * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
   * Digest ::= OCTET STRING
   *
   * To perform PSS signature verification, provide an instance
   * of Forge PSS object as the scheme parameter.
   *
   * @param digest the message digest hash to compare against the signature,
   *          as a binary-encoded string.
   * @param signature the signature to verify, as a binary-encoded string.
   * @param scheme signature verification scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'NONE' or null for none, DigestInfo will not be expected, but
   *            PKCS#1 v1.5 padding will still be used.
   * @param options optional verify options
   *          _parseAllDigestBytes testing flag to control parsing of all
   *            digest bytes. Unsupported and not for general usage.
   *            (default: true)
   *
   * @return true if the signature was verified, false if not.
   */
  key.verify = function(digest, signature, scheme, options) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSASSA-PKCS1-V1_5';
    }
    if(options === undefined) {
      options = {
        _parseAllDigestBytes: true
      };
    }
    if(!('_parseAllDigestBytes' in options)) {
      options._parseAllDigestBytes = true;
    }

    if(scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {
        verify: function(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true);
          // d is ASN.1 BER-encoded DigestInfo
          var obj = asn1.fromDer(d, {
            parseAllBytes: options._parseAllDigestBytes
          });

          // validate DigestInfo
          var capture = {};
          var errors = [];
          if(!asn1.validate(obj, digestInfoValidator, capture, errors)) {
            var error = new Error(
              'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 ' +
              'DigestInfo value.');
            error.errors = errors;
            throw error;
          }
          // check hash algorithm identifier
          // see PKCS1-v1-5DigestAlgorithms in RFC 8017
          // FIXME: add support to vaidator for strict value choices
          var oid = asn1.derToOid(capture.algorithmIdentifier);
          if(!(oid === forge.oids.md2 ||
            oid === forge.oids.md5 ||
            oid === forge.oids.sha1 ||
            oid === forge.oids.sha224 ||
            oid === forge.oids.sha256 ||
            oid === forge.oids.sha384 ||
            oid === forge.oids.sha512 ||
            oid === forge.oids['sha512-224'] ||
            oid === forge.oids['sha512-256'])) {
            var error = new Error(
              'Unknown RSASSA-PKCS1-v1_5 DigestAlgorithm identifier.');
            error.oid = oid;
            throw error;
          }

          // special check for md2 and md5 that NULL parameters exist
          if(oid === forge.oids.md2 || oid === forge.oids.md5) {
            if(!('parameters' in capture)) {
              throw new Error(
                'ASN.1 object does not contain a valid RSASSA-PKCS1-v1_5 ' +
                'DigestInfo value. ' +
                'Missing algorithm identifer NULL parameters.');
            }
          }

          // compare the given digest to the decrypted one
          return digest === capture.digest;
        }
      };
    } else if(scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      scheme = {
        verify: function(digest, d) {
          // remove padding
          d = _decodePkcs1_v1_5(d, key, true);
          return digest === d;
        }
      };
    }

    // do rsa decryption w/o any decoding, then verify -- which does decoding
    var d = pki.rsa.decrypt(signature, key, true, false);
    return scheme.verify(digest, d, key.n.bitLength());
  };

  return key;
};

/**
 * Sets an RSA private key from BigIntegers modulus, exponent, primes,
 * prime exponents, and modular multiplicative inverse.
 *
 * @param n the modulus.
 * @param e the public exponent.
 * @param d the private exponent ((inverse of e) mod n).
 * @param p the first prime.
 * @param q the second prime.
 * @param dP exponent1 (d mod (p-1)).
 * @param dQ exponent2 (d mod (q-1)).
 * @param qInv ((inverse of q) mod p)
 *
 * @return the private key.
 */
pki.setRsaPrivateKey = pki.rsa.setPrivateKey = function(
  n, e, d, p, q, dP, dQ, qInv) {
  var key = {
    n: n,
    e: e,
    d: d,
    p: p,
    q: q,
    dP: dP,
    dQ: dQ,
    qInv: qInv
  };

  /**
   * Decrypts the given data with this private key. The decryption scheme
   * must match the one used to encrypt the data.
   *
   * @param data the byte string to decrypt.
   * @param scheme the decryption scheme to use:
   *          'RSAES-PKCS1-V1_5' (default),
   *          'RSA-OAEP',
   *          'RAW', 'NONE', or null to perform raw RSA decryption.
   * @param schemeOptions any scheme-specific options.
   *
   * @return the decrypted byte string.
   */
  key.decrypt = function(data, scheme, schemeOptions) {
    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    } else if(scheme === undefined) {
      scheme = 'RSAES-PKCS1-V1_5';
    }

    // do rsa decryption w/o any decoding
    var d = pki.rsa.decrypt(data, key, false, false);

    if(scheme === 'RSAES-PKCS1-V1_5') {
      scheme = {decode: _decodePkcs1_v1_5};
    } else if(scheme === 'RSA-OAEP' || scheme === 'RSAES-OAEP') {
      scheme = {
        decode: function(d, key) {
          return forge.pkcs1.decode_rsa_oaep(key, d, schemeOptions);
        }
      };
    } else if(['RAW', 'NONE', 'NULL', null].indexOf(scheme) !== -1) {
      scheme = {decode: function(d) {return d;}};
    } else {
      throw new Error('Unsupported encryption scheme: "' + scheme + '".');
    }

    // decode according to scheme
    return scheme.decode(d, key, false);
  };

  /**
   * Signs the given digest, producing a signature.
   *
   * PKCS#1 supports multiple (currently two) signature schemes:
   * RSASSA-PKCS1-V1_5 and RSASSA-PSS.
   *
   * By default this implementation uses the "old scheme", i.e.
   * RSASSA-PKCS1-V1_5. In order to generate a PSS signature, provide
   * an instance of Forge PSS object as the scheme parameter.
   *
   * @param md the message digest object with the hash to sign.
   * @param scheme the signature scheme to use:
   *          'RSASSA-PKCS1-V1_5' or undefined for RSASSA PKCS#1 v1.5,
   *          a Forge PSS object for RSASSA-PSS,
   *          'NONE' or null for none, DigestInfo will not be used but
   *            PKCS#1 v1.5 padding will still be used.
   *
   * @return the signature as a byte string.
   */
  key.sign = function(md, scheme) {
    /* Note: The internal implementation of RSA operations is being
      transitioned away from a PKCS#1 v1.5 hard-coded scheme. Some legacy
      code like the use of an encoding block identifier 'bt' will eventually
      be removed. */

    // private key operation
    var bt = false;

    if(typeof scheme === 'string') {
      scheme = scheme.toUpperCase();
    }

    if(scheme === undefined || scheme === 'RSASSA-PKCS1-V1_5') {
      scheme = {encode: emsaPkcs1v15encode};
      bt = 0x01;
    } else if(scheme === 'NONE' || scheme === 'NULL' || scheme === null) {
      scheme = {encode: function() {return md;}};
      bt = 0x01;
    }

    // encode and then encrypt
    var d = scheme.encode(md, key.n.bitLength());
    return pki.rsa.encrypt(d, key, bt);
  };

  return key;
};

/**
 * Wraps an RSAPrivateKey ASN.1 object in an ASN.1 PrivateKeyInfo object.
 *
 * @param rsaKey the ASN.1 RSAPrivateKey.
 *
 * @return the ASN.1 PrivateKeyInfo.
 */
pki.wrapRsaPrivateKey = function(rsaKey) {
  // PrivateKeyInfo
  return
    asn1.create(asn1.Class.UNIVERSAL,
                     asn1.Type.SEQUENCE,
                     true,
                     [
    // version (0)
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.INTEGER,
                false,
                asn1.integerToDer(0).getBytes()),
    // privateKeyAlgorithm
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.SEQUENCE,
                true,
                [
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.OID,
                  false,
                  asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.NULL,
                  false,
                  '')
    ]),
    // PrivateKey
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.OCTETSTRING,
                false,
                asn1.toDer(rsaKey).getBytes())
  ]);
};

#endif
namespace Forge
{
namespace PKI
{
namespace V2
{
template<typename KeyType>
juce::var wrapRsaPrivateKey(const KeyType& rsaKey)
{
    using namespace Forge::ASN1::V2;
    // PrivateKeyInfo
    auto oid = Forge::PKI::V1::findOID("rsaEncryption");
    if( oid.isEmpty() )
    {
        jassertfalse;
        return {};
    }
    
    return
    create(ASN1::Class::UNIVERSAL,                  //return asn1.create(asn1.Class.UNIVERSAL,
        ASN1::Type::SEQUENCE,                       //    asn1.Type.SEQUENCE,
        true,                                       //    true,
        juce::Array<juce::var>{                     //    [
            // version (0)                          //     // version (0)
            create(ASN1::Class::UNIVERSAL,          //     asn1.create(asn1.Class.UNIVERSAL,
                ASN1::Type::INTEGER,                //        asn1.Type.INTEGER,
                false,                              //        false,
                Forge::ASN1::V2::integerToDer(0)),  //        asn1.integerToDer(0).getBytes()),
            // privateKeyAlgorithm                  //    // privateKeyAlgorithm
            create(ASN1::Class::UNIVERSAL,          //    asn1.create(asn1.Class.UNIVERSAL,
                ASN1::Type::SEQUENCE,               //        asn1.Type.SEQUENCE,
                true,                               //        true,
                juce::Array<juce::var>{             //        [
                    create(ASN1::Class::UNIVERSAL,  //         asn1.create(asn1.Class.UNIVERSAL,
                        ASN1::Type::OID,            //            asn1.Type.OID,
                        false,                      //            false,
                        ASN1::V1::oidToDer(oid)),   //            asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
                    create(ASN1::Class::UNIVERSAL,  //         asn1.create(asn1.Class.UNIVERSAL,
                        ASN1::Type::NULL_,          //            asn1.Type.NULL,
                        false,                      //            false,
                        juce::var())                //            '')
                }                                   //    ]
                ),                                  //    ),
                 // PrivateKey                      //    // PrivateKey
            create(ASN1::Class::UNIVERSAL,          //    asn1.create(asn1.Class.UNIVERSAL,
                ASN1::Type::OCTETSTRING,            //                asn1.Type.OCTETSTRING,
                false,                              //                false,
                Forge::ASN1::V2::toDer(rsaKey))     //                asn1.toDer(rsaKey).getBytes())
        }                                           //]
        );                                          //);
    
    /*
    return
    create(ASN1::Class::UNIVERSAL,
           ASN1::Type::SEQUENCE,
           true,
           juce::Array<juce::var>{
        //[
               // version (0)
               create(ASN1::Class::UNIVERSAL,
                      ASN1::Type::INTEGER,
                      false,
                      //asn1.integerToDer(0).getBytes()),
                      Forge::ASN1::V2::integerToDer(0)),
               // privateKeyAlgorithm
               create(ASN1::Class::UNIVERSAL,
                      ASN1::Type::SEQUENCE,
                      true,
                      juce::Array<juce::var>{//[
                          create(ASN1::Class::UNIVERSAL,
                                 ASN1::Type::OID,
                                 false,
                                 //asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
                                 ASN1::V1::oidToDer(oid)),
                          create(ASN1::Class::UNIVERSAL,
                                 ASN1::Type::NULL_,
                                 false,
                                 juce::var{})
                      //]),
               }),
               // PrivateKey
               create(ASN1::Class::UNIVERSAL,
                      ASN1::Type::OCTETSTRING,
                      false,
//                      asn1.toDer(rsaKey).getBytes())
                      Forge::ASN1::V2::toDer(rsaKey))
//           ]);
    });
     */
}
/**
 * Converts a private key from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a PrivateKeyInfo containing an
 *          RSAPrivateKey or an RSAPrivateKey.
 *
 * @return the private key.
 */
/*
pki.privateKeyFromAsn1 = function(obj) {
  // get PrivateKeyInfo
  var capture = {};
  var errors = [];
  if(asn1.validate(obj, privateKeyValidator, capture, errors)) {
    obj = asn1.fromDer(forge.util.createBuffer(capture.privateKey));
  }

  // get RSAPrivateKey
  capture = {};
  errors = [];
  if(!asn1.validate(obj, rsaPrivateKeyValidator, capture, errors)) {
    var error = new Error('Cannot read private key. ' +
      'ASN.1 object does not contain an RSAPrivateKey.');
    error.errors = errors;
    throw error;
  }

  // Note: Version is currently ignored.
  // capture.privateKeyVersion
  // FIXME: inefficient, get a BigInteger that uses byte strings
  var n, e, d, p, q, dP, dQ, qInv;
  n = forge.util.createBuffer(capture.privateKeyModulus).toHex();
  e = forge.util.createBuffer(capture.privateKeyPublicExponent).toHex();
  d = forge.util.createBuffer(capture.privateKeyPrivateExponent).toHex();
  p = forge.util.createBuffer(capture.privateKeyPrime1).toHex();
  q = forge.util.createBuffer(capture.privateKeyPrime2).toHex();
  dP = forge.util.createBuffer(capture.privateKeyExponent1).toHex();
  dQ = forge.util.createBuffer(capture.privateKeyExponent2).toHex();
  qInv = forge.util.createBuffer(capture.privateKeyCoefficient).toHex();

  // set private key
  return pki.setRsaPrivateKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16),
    new BigInteger(d, 16),
    new BigInteger(p, 16),
    new BigInteger(q, 16),
    new BigInteger(dP, 16),
    new BigInteger(dQ, 16),
    new BigInteger(qInv, 16));
};
*/
//namespace Forge
//{
//namespace PKI
//{
//namespace V2
//{
template<typename KeyType>
KeyType privateKeyFromAsn1(juce::var obj)
{
    // get PrivateKeyInfo
    juce::var capture(new juce::DynamicObject()); //var capture = {}
    juce::StringArray errors; //var errors = [];
    if(Forge::ASN1::V2::validate(obj, Forge::RSA::V2::getPrivateKeyValidator(), capture, errors)) //if(asn1.validate(obj, privateKeyValidator, capture, errors))
    {
        //obj = asn1.fromDer(forge.util.createBuffer(capture.privateKey));
        jassert(capture.hasProperty("privateKey"));
        jassert(capture["privateKey"].isBinaryData());
        auto block = *capture["privateKey"].getBinaryData();
        obj = Forge::ASN1::V2::fromDer(block, {});
    }
    else
    {
        DBG( "failed to validate obj against Private Key Validator" );
        DBG( "errors: ");
        for( auto e : errors )
            DBG( e );
        
        jassertfalse;
        return {};
    }
    
    // get RSA params
    capture = juce::var(new juce::DynamicObject()); //capture = {};
    errors.clear(); //errors = [];
    if(!Forge::ASN1::V2::validate(obj, Forge::RSA::V2::getRsaPrivateKeyValidator(), capture, errors)) //if(!asn1.validate(obj, rsaPrivateKeyValidator, capture, errors))
    {
//        var error = new Error('Cannot read public key. ' +
//                              'ASN.1 object does not contain an RSAPublicKey.');
//        error.errors = errors;
//        throw error;
        DBG( "Cannot read public key");
        DBG( "ASN.1 object does not contain an RSAPrivateKey");
        DBG( "errors during validation:" );
        for( auto e : errors )
        {
            DBG( e );
        }
        jassertfalse;
        return {};
    }
    
    // FIXME: inefficient, get a BigInteger that uses byte strings
    auto getHexFromProp = [&capture](juce::Identifier property)
    {
        jassert(capture.hasProperty(property));
        jassert(capture[property].isBinaryData());
        const auto& modMB = *capture[property].getBinaryData();
        return juce::String::toHexString(modMB.getData(),
                                         modMB.getSize(),
                                         0);
    };
    auto n = getHexFromProp("privateKeyModulus");
    auto e = getHexFromProp("privateKeyPublicExponent");
    auto d = getHexFromProp("privateKeyPrivateExponent");
    auto p = getHexFromProp("privateKeyPrime1");
    auto q = getHexFromProp("privateKeyPrime2");
    auto dP = getHexFromProp("privateKeyExponent1");
    auto dQ = getHexFromProp("privateKeyExponent2");
    auto qInv = getHexFromProp("privateKeyCoefficient");
    
    DBG( "\n\n\n\n" );
    DBG( "n: " << n );
    DBG( "e: " << e );
    DBG( "d: " << d );
    DBG( "p: " << p );
    DBG( "q: " << q );
    DBG( "dP: " << dP );
    DBG( "dQ: " << dQ );
    DBG( "qInv: " << qInv );
    DBG( "\n\n\n\n" );
    
    auto getBigInt = [](juce::String hex) -> juce::BigInteger
    {
        auto bi = juce::BigInteger();
        bi.parseString(hex, 16);
        return bi;
    };
    
    auto n_bi = getBigInt( n );
    auto e_bi = getBigInt( e );
    auto d_bi = getBigInt( d );
    auto p_bi = getBigInt( p );
    auto q_bi = getBigInt( q );
    auto dP_bi = getBigInt( dP );
    auto dQ_bi = getBigInt( dQ );
    auto qInv_bi = getBigInt( qInv);
    // set private key
    /*
    return pki.setRsaPrivateKey(
      new BigInteger(n, 16),
      new BigInteger(e, 16),
      new BigInteger(d, 16),
      new BigInteger(p, 16),
      new BigInteger(q, 16),
      new BigInteger(dP, 16),
      new BigInteger(dQ, 16),
      new BigInteger(qInv, 16));
     */
    return KeyType
    {
        n_bi,
        e_bi,
        d_bi,
        p_bi,
        q_bi,
        dP_bi,
        dQ_bi,
        qInv_bi
    };
}

} //end namespace V2
} //end namespace PKI
} //end namespace Forge
#if false
/**
 * Converts a private key to an ASN.1 RSAPrivateKey.
 *
 * @param key the private key.
 *
 * @return the ASN.1 representation of an RSAPrivateKey.
 */
pki.privateKeyToAsn1 = pki.privateKeyToRSAPrivateKey = function(key) {
  // RSAPrivateKey
  return asn1.create(asn1.Class.UNIVERSAL,
                     asn1.Type.SEQUENCE,
                     true,
                     [
    // version (0 = only 2 primes, 1 multiple primes)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     asn1.integerToDer(0).getBytes()),
                         // modulus (n)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.n)),
                         // publicExponent (e)
                         asn1.create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.e)),
                         // privateExponent (d)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.d)),
                         // privateKeyPrime1 (p)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.p)),
                         // privateKeyPrime2 (q)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.q)),
                         // privateKeyExponent1 (dP)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.dP)),
                         // privateKeyExponent2 (dQ)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.dQ)),
                         // coefficient (qInv)
                         asn1.create(asn1.Class.UNIVERSAL,
                                     asn1.Type.INTEGER,
                                     false,
                                     _bnToBytes(key.qInv))
  ]);
};
#endif
namespace Forge
{
namespace PKI
{
namespace V2
{
template<typename KeyType>
juce::var privateKeyToAsn1(const KeyType& key)
{
    // RSAPrivateKey
    using namespace Forge::ASN1::V2;
    return create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                  ASN1::Type::SEQUENCE,//asn1.Type.SEQUENCE,
                  true,
                  juce::Array<juce::var>{//[
      // version (0 = only 2 primes, 1 multiple primes)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
//                                  asn1.integerToDer(0).getBytes()),
                                  Forge::ASN1::V2::integerToDer(0)),
                           // modulus (n)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getN())),
                           // publicExponent (e)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getE())),
                           // privateExponent (d)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getD())),
                           // privateKeyPrime1 (p)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getP())),
                           // privateKeyPrime2 (q)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getQ())),
                           // privateKeyExponent1 (dP)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.get_dP())),
                           // privateKeyExponent2 (dQ)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.get_dQ())),
                           // coefficient (qInv)
                           create(ASN1::Class::UNIVERSAL,//asn1.Class.UNIVERSAL,
                                  ASN1::Type::INTEGER,//asn1.Type.INTEGER,
                                  false,
                                  Forge::PKI::V2::_bnToBytes(key.getQInv()))
//    ]);
    });
}
} //end namespace V2
} //end namespace PKI
} //end namespace Forge
/**
 * Converts a public key from an ASN.1 SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @param obj the asn1 representation of a SubjectPublicKeyInfo or RSAPublicKey.
 *
 * @return the public key.
 */
namespace Forge
{
namespace PKI
{
namespace V1
{
struct JSBigIntData
{
    std::vector<juce::int32> values;
    bool empty() const { return values.empty(); }
    size_t size() const { return values.size(); }
    juce::int32& operator[](size_t idx)
    {
        if( juce::isPositiveAndBelow(idx, values.size()) )
            return values[idx];
        
        while( idx >= values.size() )
        {
            values.push_back(0);
        }
        
        return values[idx];
    }
    juce::int32 operator[](size_t idx) const
    {
        if( juce::isPositiveAndBelow(idx, values.size()) )
            return values[idx];
        
        return -1;
    }
    
};
struct JSBigInt
{
    int s = 0;
    int t = 0;
    JSBigIntData data;
    
//        if(typeof(navigator) === 'undefined')
//        {
//           BigInteger.prototype.am = am3;
//           dbits = 28;
    //BigInteger.prototype.DM = ((1<<dbits)-1);
    static constexpr juce::uint32 dbits = 28;
    //BigInteger.prototype.DB = dbits;
    static constexpr juce::uint32 DB = dbits;
    static constexpr juce::uint32 DM = ((1 << dbits) - 1);
    //BigInteger.prototype.DV = (1<<dbits);
    static constexpr juce::uint32 DV = (1 << dbits);
    
    void fromInt(int x)
    {
        this->t = 1;
        this->s = (x < 0) ? -1 : 0;
        if(x > 0) this->data[0] = x;
        else if(x < -1) this->data[0] = x + this->DV;
        else this->t = 0;
    }
    
    // return bigint initialized to value
//    function nbv(i) { var r = nbi(); r.fromInt(i); return r; }
    static JSBigInt nbv(int i)
    {
        JSBigInt r;
        r.fromInt(i);
        return r;
    }
    
    static inline const JSBigIntData& getBI_RC()
    {
//            var BI_RC = new Array();
        static JSBigIntData BI_RC;
        if( BI_RC.empty() )
        {
//                var rr,vv;
//                rr = "0".charCodeAt(0);
            juce::uint8 rr = '0';
            juce::uint8 vv;
            for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
//                rr = "a".charCodeAt(0);
            rr = 'a';
            for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
//                rr = "A".charCodeAt(0);
            rr = 'A';
            for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
        }
        
        return BI_RC;
    }
    
    int intAt(juce::String s, int i)
    {
//            var c = BI_RC[s.charCodeAt(i)];
//            return (c==null)?-1:c;
        if( i < s.length() - 1)
        {
            auto idx = s[i]; //String::operator[] returns a juce_wchar
            const auto& BI_RC = getBI_RC();
            if( juce::isPositiveAndBelow(idx, BI_RC.size()) )
            {
                return BI_RC[idx];
            }
        }
        
        return -1;
    }
    
    void clamp()
    {
        juce::uint32 c = s & DM;
        while(t > 0 && data[t - 1] == c)
            --t;
    }
    
    void fromString(juce::String s, int b)
    {
        int k;
        if(b == 16) k = 4;
        else if(b == 8) k = 3;
        else if(b == 256) k = 8; // byte array
        else if(b == 2) k = 1;
        else if(b == 32) k = 5;
        else if(b == 4) k = 2;
        else
        {
            jassertfalse;
//                fromRadix(s,b);
            return;
        }
        this->t = 0;
        this->s = 0;
//            var i = s.length, mi = false, sh = 0;
        int i = s.length();
        bool mi = false;
        int sh = 0;
        while(--i >= 0)
        {
//                var x = (k == 8) ? s[i] & 0xff : intAt(s,i);
            int x = (k == 8) ? s.substring(i, 1).getIntValue() & 0xFF : intAt(s, i);
            if(x < 0)
            {
//                    if(s.charAt(i) == "-")
                if( s.substring(i, 1) == "-")
                    mi = true;
                continue;
            }
            
            mi = false;
            if(sh == 0)
            {
                this->data[this->t++] = x;
            }
            else if(sh + k > this->DB)
            {
                this->data[this->t - 1] |= (x & ((1 << (this->DB - sh)) - 1)) << sh;
                this->data[this->t++] = (x >> (this->DB - sh));
            }
            else
            {
                this->data[this->t - 1] |= x << sh;
            }
            sh += k;
            if(sh >= this->DB)
                sh -= this->DB;
        }
        if(k == 8 && (s[0] & 0x80) != 0)
        {
            this->s = -1;
            if(sh > 0)
                this->data[this->t - 1] |= ((1 << (this->DB - sh)) - 1) << sh;
        }
        this->clamp();
        if(mi)
        {
//            BigInteger.ZERO.subTo(this,this);
            ZERO().subTo(*this, *this);
        }
    }
    
    static JSBigInt ZERO()
    {
        static JSBigInt z = nbv(0);
        return z;
    }
    
    void subTo(const JSBigInt& a, JSBigInt& r)
    {
//            var i = 0, c = 0, m = Math.min(a.t, this->t);
        int i = 0;
        int c = 0;
        int m = juce::jmin(a.t, this->t);
        while(i < m)
        {
            c += this->data[i] - a.data[i];
            r.data[i++] = c & this->DM;
            c >>= this->DB;
        }
        if(a.t < this->t)
        {
            c -= a.s;
            while(i < this->t)
            {
                c += this->data[i];
                r.data[i++] = c & this->DM;
                c >>= this->DB;
            }
            c += this->s;
        }
        else
        {
            c += this->s;
            while(i < a.t)
            {
                c -= a.data[i];
                r.data[i++] = c & this->DM;
                c >>= this->DB;
            }
            c -= a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if(c < -1)
            r.data[i++] = this->DV + c;
        else if(c > 0)
            r.data[i++] = c;
        r.t = i;
        r.clamp();
    }
};

template<typename T, typename U>
struct IsReferenceCountedType : std::false_type { };

template<typename U>
struct IsReferenceCountedType<juce::ReferenceCountedObjectPtr<U>, U> : std::true_type { };

template<typename ReturnType, typename ASNType>
ReturnType publicKeyFromASN1(ASNType obj)
{
    static_assert(IsReferenceCountedType<ASNType, typename ASNType::ReferencedType>::value, "ASNType must be an instance of a juce::ReferenceCountedObjectPtr");
//pki.publicKeyFromAsn1 = function(obj) {
  // get SubjectPublicKeyInfo
//  var capture = {};
    /*
     In javascript, 'var name = {};' defines an empty object
     Objects are passed by reference, not by copy.
     You can use this syntax to declare properties (member variables) of objects:
     
     var obj = {};
     obj['name'] = value;
     
     you can then access that property using 'dot' syntax:
     
     obj.name = newValue;
     
     the 'capture' object is used this way.
     the 'validate' function adds properties to capture dynamically.
     However, there is a fixed set of properties being added,
     and those properties come from the Validator instance used.
     */
    Forge::ASN1::V1::Capture::Ptr capture = new Forge::ASN1::V1::Capture();
//  var errors = [];
    std::vector<juce::String> errors;
    
//  if(asn1.validate(obj, publicKeyValidator, capture, errors)) {
    auto publicKeyValidator = Forge::RSA::V1::getPublicKeyValidator();
    if( Forge::ASN1::V1::validate(*obj, *publicKeyValidator, capture, errors))
    {
        // get oid
//        var oid = asn1.derToOid(capture.publicKeyOid);
        auto data = capture->get("publicKeyOid");
        jassert(data != juce::var() );
        jassert(data.isArray());
        if(! data.isArray() )
        {
            jassertfalse;
            return {};
        }
        
        auto oidPtr = Forge::ASN1::V1::ASNObject::fromVar(data);
        
        
//        auto block = oidPtr->byteArray;
        jassert(! oidPtr->byteArray.isEmpty() );
        auto oid = Forge::ASN1::V1::derToOid(oidPtr->byteArray);
//        if(oid !== pki.oids.rsaEncryption)
        const auto& oids = Forge::PKI::oids();
        if( oids.find(oid) == oids.end() )
        {
//            var error = new Error('Cannot read public key. Unknown OID.');
            DBG( "Cannot read public key. Unknown OID.");
//            error.oid = oid;
//            throw error;
            jassertfalse;
            return {}; //returns an invalid key
        }
        data = capture->get("rsaPublicKey");
        jassert(data != juce::var() );
        jassert(data.isArray());
        if(! data.isArray() )
        {
            jassertfalse;
            return {};
        }
        obj = Forge::ASN1::V1::ASNObject::fromVar(data);
    }
    
    // get RSA params
//    errors = [];
    errors.clear();
    
//    if(!asn1.validate(obj, rsaPublicKeyValidator, capture, errors))
    auto rsaPublicKeyValidator = Forge::RSA::V1::getRSAPublicKeyValidator();
    if( !Forge::ASN1::V1::validate(*obj, *rsaPublicKeyValidator, capture, errors) )
    {
//        var error = new Error('Cannot read public key. ' +
//                              'ASN.1 object does not contain an RSAPublicKey.');
//        error.errors = errors;
//        throw error;
        DBG( "Cannot read public key. ASN.1 object does not contain an RSAPublicKey." );
        jassertfalse;
        return {}; //returns an invalid key
    }
    
    // FIXME: inefficient, get a BigInteger that uses byte strings
//    var n = forge.util.createBuffer(capture.publicKeyModulus).toHex();
//    var e = forge.util.createBuffer(capture.publicKeyExponent).toHex();
//
//    // set public key
//    return pki.setRsaPublicKey(
//                               new BigInteger(n, 16),
//                               new BigInteger(e, 16));
    juce::BigInteger n, e;
    auto data = capture->get("publicKeyModulus");
    jassert(data != juce::var() );
    jassert(data.isBinaryData());
    if(! data.isBinaryData() )
    {
        jassertfalse;
        return {};
    }
//    obj = Forge::ASN1::ASNObject::fromVar(data);
    auto nblock = *data.getBinaryData();

//    //switch endianness
//    for( int i = 0; i < nblock.getSize(); ++i )
//    {
//        juce::uint32 v = nblock.getBitRange(i * 32, 32);
//        v = juce::ByteOrder::swap(v);
//        nblock.setBitRange(i * 32, 32, v);
//    }
//    auto b64 = nblock.toBase64Encoding();
    auto hex = juce::String::toHexString(nblock.getData(), nblock.getSize());
//    n.loadFromMemoryBlock( nblock );
    
    auto jsBigInt = JSBigInt();
    jsBigInt.fromString(hex, 16);
    
    n.parseString(hex, 16);
    
    data = capture->get("publicKeyExponent");
    jassert(data != juce::var() );
    jassert(data.isBinaryData());
    if(! data.isBinaryData() )
    {
        jassertfalse;
        return {};
    }
    
//    auto& modulusMemBlock = *data.getBinaryData();
//
//    for( int i = 0; i < modulusMemBlock.getSize(); ++i )
//    {
//        DBG( "[" << i << "]: " << modulusMemBlock.getBitRange(i*8, 8) );
//    }
    
//    obj = Forge::ASN1::ASNObject::fromVar(data);
    e.loadFromMemoryBlock(*data.getBinaryData());
#if false
    for( int i = 0; i < n.getHighestBit(); i += sizeof(juce::uint32)*8)
    {
        int index = i / (sizeof(juce::uint32)*8);
        juce::uint32 val = n.getBitRangeAsInt(i, sizeof(juce::uint32)*8);
        DBG("[" << index << "]: " << juce::String(val) << " [" << std::bitset<sizeof(juce::uint32)*8>(val).to_string() << "]" );
    }
#endif
    for( size_t i = 0; i < jsBigInt.data.values.size(); ++i )
    {
        juce::uint32 val = static_cast<juce::uint32>(jsBigInt.data[i]);
        DBG("[" <<  i << "]: " << juce::String(val) << " [" << std::bitset<sizeof(juce::uint32)*8>(val).to_string() << "]" );
    }
    
    jassertfalse;
    
    auto key = ReturnType(n.toString(16) + "," + e.toString(16));
    if(key.isValid())
        return key;
    jassertfalse;
    return {}; //returns an invalid key
}
} //end namespace V1
namespace V2
{
template<typename ReturnType>
ReturnType publicKeyFromASN1(juce::var obj)
{
    // get SubjectPublicKeyInfo
    juce::var capture(new juce::DynamicObject());
    juce::StringArray errors;
    if(ASN1::V2::validate(obj, Forge::RSA::V2::getPublicKeyValidator(), capture, errors))
    {
        // get oid
//        juce::var oid = asn1.derToOid(capture.publicKeyOid);
        auto oidMb = *capture["publicKeyOid"].getBinaryData();
        auto oidStr = ASN1::V1::derToOid(oidMb);
        const auto& oids = Forge::PKI::oids();
        if( oids.find(oidStr) == oids.end() )
        {
//            var error = new Error('Cannot read public key. Unknown OID.');
//            error.oid = oid;
//            throw error;
            DBG( "Cannot read public key.  Unknown OID" );
            DBG( "OID: " << oidStr );
            jassertfalse;
            return {};
        }
        jassert(capture.hasProperty("rsaPublicKey"));
        obj = capture["rsaPublicKey"];
    }
    
    // get RSA params
    errors.clear();
    if(!ASN1::V2::validate(obj, Forge::RSA::V2::getRSAPublicKeyValidator(), capture, errors))
    {
//        var error = new Error('Cannot read public key. ' +
//                              'ASN.1 object does not contain an RSAPublicKey.');
//        error.errors = errors;
//        throw error;
        DBG( "Cannot read public key");
        DBG( "ASN.1 object does not contain an RSAPublicKey");
        DBG( "errors during validation:" );
        for( auto e : errors )
        {
            DBG( e );
        }
        jassertfalse;
        return {};
    }
    
    // FIXME: inefficient, get a BigInteger that uses byte strings
//    var n = forge.util.createBuffer(capture.publicKeyModulus).toHex();
//    var e = forge.util.createBuffer(capture.publicKeyExponent).toHex();
    jassert(capture.hasProperty("publicKeyModulus"));
    jassert(capture["publicKeyModulus"].isBinaryData());
    const auto& modMB = *capture["publicKeyModulus"].getBinaryData();
    auto n = juce::String::toHexString(modMB.getData(), modMB.getSize(), 0);
    
    jassert(capture.hasProperty("publicKeyExponent"));
    jassert(capture["publicKeyExponent"].isBinaryData());
    const auto& expMB = *capture["publicKeyExponent"].getBinaryData();
    auto e = juce::String::toHexString(expMB.getData(), expMB.getSize(), 0);
    
    DBG( "\n\n\n\n" );
    DBG( "n: " << n );
    DBG( "e: " << e );
    DBG( "\n\n\n\n" );
    // set public key
    auto nbi = juce::BigInteger();
    nbi.parseString(n, 16);
    DBG( "nbi: " << nbi.toString(16));
    auto ebi = juce::BigInteger();
    ebi.parseString(e, 16);
    DBG( "ebi: " << ebi.toString(16));
    
#if false
    constexpr int bitIncrement = sizeof(juce::uint32) * 8;
    for( int i = 0; i < nbi.getHighestBit(); i += bitIncrement)
    {
        int index = i / (bitIncrement);
        juce::uint32 val = nbi.getBitRangeAsInt(i, bitIncrement);
        DBG("[" << index << "]: " << juce::String(val) << " [" << std::bitset<bitIncrement>(val).to_string() << "]" );
    }
#endif
    
    return ReturnType(nbi, ebi);
//    return pki.setRsaPublicKey(
//                               new BigInteger(n, 16),
//                               new BigInteger(e, 16));
};
} //end namespace V2
} //end namespace PKI
} //end namespace forge
#if false
/**
 * Converts a public key to an ASN.1 SubjectPublicKeyInfo.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a SubjectPublicKeyInfo.
 */
#endif
namespace Forge
{
namespace PKI
{
namespace V2
{
//forward declaration, for use in publicKeyToAsn1():
template<typename KeyType>
juce::var publicKeyToRSAPublicKey(const KeyType& key);

template<typename KeyType>
juce::var publicKeyToAsn1(const KeyType& key)
{
  // SubjectPublicKeyInfo
#if false
  return asn1.create(asn1.Class.UNIVERSAL,
                     asn1.Type.SEQUENCE,
                     true,
                     [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.SEQUENCE,
                true,
                [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.OID,
                  false,
                  asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.NULL,
                  false, '')
    ]),
    // subjectPublicKey
    asn1.create(asn1.Class.UNIVERSAL,
                asn1.Type.BITSTRING,
                false,
                [
                    pki.publicKeyToRSAPublicKey(key)
    ])
  ]);
#endif

    const auto& oids = PKI::oids();
    auto oid = Forge::PKI::V1::findOID("rsaEncryption");
    
    if( oid.isEmpty() )
    {
        jassertfalse;
        return {};
    }

    using namespace Forge::ASN1::V2;
    using namespace Forge::PKI::V2;
    
#if false
    // SubjectPublicKeyInfo
    auto asn1 = create(ASN1::Class::UNIVERSAL,
                       ASN1::Type::SEQUENCE,
                       true,
                       juce::Array<juce::var>
                       {
        // AlgorithmIdentifier
        create(ASN1::Class::UNIVERSAL,
               ASN1::Type::SEQUENCE,
               true,
               juce::Array<juce::var> {
                // algorithm
            create(ASN1::Class::UNIVERSAL,
                   ASN1::Type::OID,
                   false,
                   ASN1::V1::oidToDer(oid)),
          // parameters (null)
            create(ASN1::Class::UNIVERSAL,
                   ASN1::Type::NULL_,
                   false,
                   juce::var{})
        }),
        // subjectPublicKey
        create(ASN1::Class::UNIVERSAL,
               ASN1::Type::BITSTRING,
               false,
               juce::Array<juce::var>
               {
            publicKeyToRSAPublicKey(key)
               })
                       });
    
    return asn1;
#endif
    
    
    auto asn1 = create(ASN1::Class::UNIVERSAL,                              //return asn1.create(asn1.Class.UNIVERSAL,
                       ASN1::Type::SEQUENCE,                                //                   asn1.Type.SEQUENCE,
                       true,                                                //                   true,
                       juce::Array<juce::var>{                              //                   [ //begin array
                                                                            //                       // AlgorithmIdentifier
                            create(ASN1::Class::UNIVERSAL,                  //                       asn1.create(asn1.Class.UNIVERSAL,
                                   ASN1::Type::SEQUENCE,                    //                                   asn1.Type.SEQUENCE,
                                   true,                                    //                                   true,
                                   juce::Array<juce::var>{                  //                                   [ //begin array
                                                                            //                                       // algorithm
                                        create(ASN1::Class::UNIVERSAL,      //                                       asn1.create(asn1.Class.UNIVERSAL,
                                               ASN1::Type::OID,             //                                                   asn1.Type.OID,
                                               false,                       //                                                   false,
                                               ASN1::V1::oidToDer(oid)),    //                                                   asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
                                                                            //                                       // parameters (null)
                                        create(ASN1::Class::UNIVERSAL,      //                                       asn1.create(asn1.Class.UNIVERSAL,
                                               ASN1::Type::NULL_,           //                                                   asn1.Type.NULL,
                                               false,                       //                                                   false,
                                               juce::var{})                 //                                                   '')
                                    }                                       //                                   ] //end array
                                    ),                                      //                                   ),
                                                                            //                       // subjectPublicKey
                            create(ASN1::Class::UNIVERSAL,                  //                       asn1.create(asn1.Class.UNIVERSAL,
                                   ASN1::Type::BITSTRING,                   //                                   asn1.Type.BITSTRING,
                                   false,                                   //                                   false,
                                   juce::Array<juce::var>{                  //                                   [ //begin array
                                        publicKeyToRSAPublicKey(key)        //                                       pki.publicKeyToRSAPublicKey(key)
                                    }                                       //                                   ] //end array
                                   )                                        //                                   )
                        }                                                   //                   ] //end array
                       );                                                   //                   );
    
    return asn1;
}

template<typename KeyType>
juce::var publicKeyToRSAPublicKey(const KeyType& key)
{
#if false
  // RSAPublicKey
    return asn1.create(asn1.Class.UNIVERSAL,
                       asn1.Type.SEQUENCE,
                       true,
                       [
      // modulus (n)
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.INTEGER,
                  false,
                  _bnToBytes(key.n)),
      // publicExponent (e)
      asn1.create(asn1.Class.UNIVERSAL,
                  asn1.Type.INTEGER,
                  false,
                  _bnToBytes(key.e))
    ]);
#endif
    using namespace Forge::ASN1::V2;
    return create(ASN1::Class::UNIVERSAL,
                  ASN1::Type::SEQUENCE,
                  true,
                  juce::Array<juce::var>
                  {
      // modulus (n)
      create(ASN1::Class::UNIVERSAL,
             ASN1::Type::INTEGER,
                  false,
                  _bnToBytes(key.getModulus())),
      // publicExponent (e)
      create(ASN1::Class::UNIVERSAL,
             ASN1::Type::INTEGER,
                  false,
                  _bnToBytes(key.getExponent()))
                 });
}
} //end namespace V2
namespace V1
{

juce::String findOID(juce::String oidToFind);
//forward declaration:
template<typename KeyType>
ASN1::V1::ASNObject::Ptr publicKeyToRSAPublicKey(KeyType key);
//pki.publicKeyToAsn1 = pki.publicKeyToSubjectPublicKeyInfo = function(key) {
  // SubjectPublicKeyInfo
template<typename ASNType, typename KeyType>
ASNType publicKeyToAsn1(KeyType key)
{
#if false
    // SubjectPublicKeyInfo
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // AlgorithmIdentifier
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      // algorithm
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
        asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
      // parameters (null)
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    ]),
    // subjectPublicKey
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [
      pki.publicKeyToRSAPublicKey(key)
    ])
  ]);
#endif
/*
 build up this ASN from the inside out:
 algorithm
 parameters
 
 AlgorithmIdentifier
    use objectList { algorithm, parameters }
 
 publicKeyToRSAPublicKey might be a byte array or ASNObject, but it is stuck inside the objectList of subjectPublicKey
 
 SubjectPublicKeyInfo
    use objectList { AlgorithmIdentifier, subjectPublicKey }
 
 */
    // parameters (null)
//    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
    auto parameters = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                    ASN1::Type::NULL_,
                                                    false, //not constructed
                                                    {}, //no object list
                                                    {}, //no byte array
                                                    {}); //no parse options
    
    // algorithm
//    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
//      asn1.oidToDer(pki.oids.rsaEncryption).getBytes()),
    const auto& oids = PKI::oids();
    auto oid = findOID("rsaEncryption");
    
    if( oid.isEmpty() )
    {
        jassertfalse;
        return {};
    }
    
    auto algorithmOIDasDerByteArray =  ASN1::V1::oidToDer(oid);
    auto algorithm = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                   ASN1::Type::OID,
                                                   false, //not constructed
                                                   {}, //no object list
                                                   algorithmOIDasDerByteArray,
                                                   {}); //no parse options
    
    // AlgorithmIdentifier
//    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [algorithm, parameters])
    auto AlgorithmIdentifier = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                             ASN1::Type::SEQUENCE,
                                                             true,
                                                             {algorithm, parameters},
                                                             {}, //no object list
                                                             {}); //no parse options
    
    // subjectPublicKey
//    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false, [
//      pki.publicKeyToRSAPublicKey(key)
    auto rsaPublicKey = Forge::PKI::V1::publicKeyToRSAPublicKey(key);
    auto subjectPublicKey = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                          ASN1::Type::BITSTRING,
                                                          false,
                                                          {rsaPublicKey},
                                                          {}, //no byte array,
                                                          {}); //no parse options
    
    // SubjectPublicKeyInfo
//  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
//    etc...
//    SubjectPublicKeyInfo
//       use objectList { AlgorithmIdentifier, subjectPublicKey }
    auto SubjectPublicKeyInfo = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                              ASN1::Type::SEQUENCE,
                                                              true,
                                                              {AlgorithmIdentifier, subjectPublicKey},
                                                              {},   //no byte array
                                                              {});  //no parse options
//    jassertfalse;
    return SubjectPublicKeyInfo;
//    return {};
};


/**
 * Converts a public key to an ASN.1 RSAPublicKey.
 *
 * @param key the public key.
 *
 * @return the asn1 representation of a RSAPublicKey.
 */
//pki.publicKeyToRSAPublicKey = function(key) {
template<typename KeyType>
ASN1::V1::ASNObject::Ptr publicKeyToRSAPublicKey(KeyType key)
{
#if false
  // RSAPublicKey
  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // modulus (n)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.n)),
    // publicExponent (e)
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
      _bnToBytes(key.e))
  ]);
#endif
    auto modulus = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                 ASN1::Type::INTEGER,
                                                 false,
                                                 {},    //no object list
                                                 key.getModulus().toMemoryBlock(),
                                                 {});   //no options
    auto exponent = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                  ASN1::Type::INTEGER,
                                                  false,
                                                  {},   //no object list
                                                  key.getExponent().toMemoryBlock(),
                                                  {});  //no options
    auto rsaPublicKey = ASN1::V1::create<ASN1::V1::ASNObject>(ASN1::Class::UNIVERSAL,
                                                      ASN1::Type::SEQUENCE,
                                                      true,
                                                      {modulus, exponent},
                                                      {},   //no byte array
                                                      {}); //no parse options
    
    return rsaPublicKey;
};
} //end namespace V1
} //end namespace PKI
} //end namespace Forge
#if false
/**
 * Encodes a message using PKCS#1 v1.5 padding.
 *
 * @param m the message to encode.
 * @param key the RSA key to use.
 * @param bt the block type to use, i.e. either 0x01 (for signing) or 0x02
 *          (for encryption).
 *
 * @return the padded byte buffer.
 */
function _encodePkcs1_v1_5(m, key, bt) {
  var eb = forge.util.createBuffer();

  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  /* use PKCS#1 v1.5 padding */
  if(m.length > (k - 11)) {
    var error = new Error('Message is too long for PKCS#1 v1.5 padding.');
    error.length = m.length;
    error.max = k - 11;
    throw error;
  }

  /* A block type BT, a padding string PS, and the data D shall be
    formatted into an octet string EB, the encryption block:

    EB = 00 || BT || PS || 00 || D

    The block type BT shall be a single octet indicating the structure of
    the encryption block. For this version of the document it shall have
    value 00, 01, or 02. For a private-key operation, the block type
    shall be 00 or 01. For a public-key operation, it shall be 02.

    The padding string PS shall consist of k-3-||D|| octets. For block
    type 00, the octets shall have value 00; for block type 01, they
    shall have value FF; and for block type 02, they shall be
    pseudorandomly generated and nonzero. This makes the length of the
    encryption block EB equal to k. */

  // build the encryption block
  eb.putByte(0x00);
  eb.putByte(bt);

  // create the padding
  var padNum = k - 3 - m.length;
  var padByte;
  // private key op
  if(bt === 0x00 || bt === 0x01) {
    padByte = (bt === 0x00) ? 0x00 : 0xFF;
    for(var i = 0; i < padNum; ++i) {
      eb.putByte(padByte);
    }
  } else {
    // public key op
    // pad with random non-zero values
    while(padNum > 0) {
      var numZeros = 0;
      var padBytes = forge.random.getBytes(padNum);
      for(var i = 0; i < padNum; ++i) {
        padByte = padBytes.charCodeAt(i);
        if(padByte === 0) {
          ++numZeros;
        } else {
          eb.putByte(padByte);
        }
      }
      padNum = numZeros;
    }
  }

  // zero followed by message
  eb.putByte(0x00);
  eb.putBytes(m);

  return eb;
}

/**
 * Decodes a message using PKCS#1 v1.5 padding.
 *
 * @param em the message to decode.
 * @param key the RSA key to use.
 * @param pub true if the key is a public key, false if it is private.
 * @param ml the message length, if specified.
 *
 * @return the decoded bytes.
 */
function _decodePkcs1_v1_5(em, key, pub, ml) {
  // get the length of the modulus in bytes
  var k = Math.ceil(key.n.bitLength() / 8);

  /* It is an error if any of the following conditions occurs:

    1. The encryption block EB cannot be parsed unambiguously.
    2. The padding string PS consists of fewer than eight octets
      or is inconsisent with the block type BT.
    3. The decryption process is a public-key operation and the block
      type BT is not 00 or 01, or the decryption process is a
      private-key operation and the block type is not 02.
   */

  // parse the encryption block
  var eb = forge.util.createBuffer(em);
  var first = eb.getByte();
  var bt = eb.getByte();
  if(first !== 0x00 ||
    (pub && bt !== 0x00 && bt !== 0x01) ||
    (!pub && bt != 0x02) ||
    (pub && bt === 0x00 && typeof(ml) === 'undefined')) {
    throw new Error('Encryption block is invalid.');
  }

  var padNum = 0;
  if(bt === 0x00) {
    // check all padding bytes for 0x00
    padNum = k - 3 - ml;
    for(var i = 0; i < padNum; ++i) {
      if(eb.getByte() !== 0x00) {
        throw new Error('Encryption block is invalid.');
      }
    }
  } else if(bt === 0x01) {
    // find the first byte that isn't 0xFF, should be after all padding
    padNum = 0;
    while(eb.length() > 1) {
      if(eb.getByte() !== 0xFF) {
        --eb.read;
        break;
      }
      ++padNum;
    }
  } else if(bt === 0x02) {
    // look for 0x00 byte
    padNum = 0;
    while(eb.length() > 1) {
      if(eb.getByte() === 0x00) {
        --eb.read;
        break;
      }
      ++padNum;
    }
  }

  // zero must be 0x00 and padNum must be (k - 3 - message length)
  var zero = eb.getByte();
  if(zero !== 0x00 || padNum !== (k - 3 - eb.length())) {
    throw new Error('Encryption block is invalid.');
  }

  return eb.getBytes();
}

/**
 * Runs the key-generation algorithm asynchronously, either in the background
 * via Web Workers, or using the main thread and setImmediate.
 *
 * @param state the key-pair generation state.
 * @param [options] options for key-pair generation:
 *          workerScript the worker script URL.
 *          workers the number of web workers (if supported) to use,
 *            (default: 2, -1 to use estimated cores minus one).
 *          workLoad the size of the work load, ie: number of possible prime
 *            numbers for each web worker to check per work assignment,
 *            (default: 100).
 * @param callback(err, keypair) called once the operation completes.
 */
function _generateKeyPair(state, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};

  var opts = {
    algorithm: {
      name: options.algorithm || 'PRIMEINC',
      options: {
        workers: options.workers || 2,
        workLoad: options.workLoad || 100,
        workerScript: options.workerScript
      }
    }
  };
  if('prng' in options) {
    opts.prng = options.prng;
  }

  generate();

  function generate() {
    // find p and then q (done in series to simplify)
    getPrime(state.pBits, function(err, num) {
      if(err) {
        return callback(err);
      }
      state.p = num;
      if(state.q !== null) {
        return finish(err, state.q);
      }
      getPrime(state.qBits, finish);
    });
  }

  function getPrime(bits, callback) {
    forge.prime.generateProbablePrime(bits, opts, callback);
  }

  function finish(err, num) {
    if(err) {
      return callback(err);
    }

    // set q
    state.q = num;

    // ensure p is larger than q (swap them if not)
    if(state.p.compareTo(state.q) < 0) {
      var tmp = state.p;
      state.p = state.q;
      state.q = tmp;
    }

    // ensure p is coprime with e
    if(state.p.subtract(BigInteger.ONE).gcd(state.e)
      .compareTo(BigInteger.ONE) !== 0) {
      state.p = null;
      generate();
      return;
    }

    // ensure q is coprime with e
    if(state.q.subtract(BigInteger.ONE).gcd(state.e)
      .compareTo(BigInteger.ONE) !== 0) {
      state.q = null;
      getPrime(state.qBits, finish);
      return;
    }

    // compute phi: (p - 1)(q - 1) (Euler's totient function)
    state.p1 = state.p.subtract(BigInteger.ONE);
    state.q1 = state.q.subtract(BigInteger.ONE);
    state.phi = state.p1.multiply(state.q1);

    // ensure e and phi are coprime
    if(state.phi.gcd(state.e).compareTo(BigInteger.ONE) !== 0) {
      // phi and e aren't coprime, so generate a new p and q
      state.p = state.q = null;
      generate();
      return;
    }

    // create n, ensure n is has the right number of bits
    state.n = state.p.multiply(state.q);
    if(state.n.bitLength() !== state.bits) {
      // failed, get new q
      state.q = null;
      getPrime(state.qBits, finish);
      return;
    }

    // set keys
    var d = state.e.modInverse(state.phi);
    state.keys = {
      privateKey: pki.rsa.setPrivateKey(
        state.n, state.e, d, state.p, state.q,
        d.mod(state.p1), d.mod(state.q1),
        state.q.modInverse(state.p)),
      publicKey: pki.rsa.setPublicKey(state.n, state.e)
    };

    callback(null, state.keys);
  }
}

/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes.
 *
 * @param b the big integer to convert.
 *
 * @return the bytes.
 */
function _bnToBytes(b) {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  var bytes = forge.util.hexToBytes(hex);

  // ensure integer is minimally-encoded
  if(bytes.length > 1 &&
    // leading 0x00 for positive integer
    ((bytes.charCodeAt(0) === 0 &&
    (bytes.charCodeAt(1) & 0x80) === 0) ||
    // leading 0xFF for negative integer
    (bytes.charCodeAt(0) === 0xFF &&
    (bytes.charCodeAt(1) & 0x80) === 0x80))) {
    return bytes.substr(1);
  }
  return bytes;
}

/**
 * Returns the required number of Miller-Rabin tests to generate a
 * prime with an error probability of (1/2)^80.
 *
 * See Handbook of Applied Cryptography Chapter 4, Table 4.4.
 *
 * @param bits the bit size.
 *
 * @return the required number of iterations.
 */
function _getMillerRabinTests(bits) {
  if(bits <= 100) return 27;
  if(bits <= 150) return 18;
  if(bits <= 200) return 15;
  if(bits <= 250) return 12;
  if(bits <= 300) return 9;
  if(bits <= 350) return 8;
  if(bits <= 400) return 7;
  if(bits <= 500) return 6;
  if(bits <= 600) return 5;
  if(bits <= 800) return 4;
  if(bits <= 1250) return 3;
  return 2;
}

/**
 * Performs feature detection on the Node crypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
function _detectNodeCrypto(fn) {
  return forge.util.isNodejs && typeof _crypto[fn] === 'function';
}

/**
 * Performs feature detection on the SubtleCrypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
function _detectSubtleCrypto(fn) {
  return (typeof util.globalScope !== 'undefined' &&
    typeof util.globalScope.crypto === 'object' &&
    typeof util.globalScope.crypto.subtle === 'object' &&
    typeof util.globalScope.crypto.subtle[fn] === 'function');
}

/**
 * Performs feature detection on the deprecated Microsoft Internet Explorer
 * outdated SubtleCrypto interface. This function should only be used after
 * checking for the modern, standard SubtleCrypto interface.
 *
 * @param fn the feature (function) to detect.
 *
 * @return true if detected, false if not.
 */
function _detectSubtleMsCrypto(fn) {
  return (typeof util.globalScope !== 'undefined' &&
    typeof util.globalScope.msCrypto === 'object' &&
    typeof util.globalScope.msCrypto.subtle === 'object' &&
    typeof util.globalScope.msCrypto.subtle[fn] === 'function');
}

function _intToUint8Array(x) {
  var bytes = forge.util.hexToBytes(x.toString(16));
  var buffer = new Uint8Array(bytes.length);
  for(var i = 0; i < bytes.length; ++i) {
    buffer[i] = bytes.charCodeAt(i);
  }
  return buffer;
}

function _privateKeyFromJwk(jwk) {
  if(jwk.kty !== 'RSA') {
    throw new Error(
      'Unsupported key algorithm "' + jwk.kty + '"; algorithm must be "RSA".');
  }
  return pki.setRsaPrivateKey(
    _base64ToBigInt(jwk.n),
    _base64ToBigInt(jwk.e),
    _base64ToBigInt(jwk.d),
    _base64ToBigInt(jwk.p),
    _base64ToBigInt(jwk.q),
    _base64ToBigInt(jwk.dp),
    _base64ToBigInt(jwk.dq),
    _base64ToBigInt(jwk.qi));
}

function _publicKeyFromJwk(jwk) {
  if(jwk.kty !== 'RSA') {
    throw new Error('Key algorithm must be "RSA".');
  }
  return pki.setRsaPublicKey(
    _base64ToBigInt(jwk.n),
    _base64ToBigInt(jwk.e));
}

function _base64ToBigInt(b64) {
  return new BigInteger(forge.util.bytesToHex(forge.util.decode64(b64)), 16);
}

#endif
