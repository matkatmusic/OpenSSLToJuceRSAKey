/*
  ==============================================================================

    AccessibleKey.h
    Created: 6 Oct 2022 11:23:27pm
    Author:  Charles Schiermeyer

  ==============================================================================
*/

#pragma once
#include <JuceHeader.h>

struct AccessiblePublicKey : juce::RSAKey
{
    AccessiblePublicKey() = default;
    AccessiblePublicKey(const juce::BigInteger& n, //modulus
                        const juce::BigInteger& e) //public exponent
    {
        /*
         publicKey.part1 = e;
         publicKey.part2 = n;

         privateKey.part1 = d;
         privateKey.part2 = n;
         */
        part1 = e;
        part2 = n;
    }
    
    auto& getModulus() { return part2; }
    const auto& getModulus() const { return part2; }
    
    auto& getExponent() { return part1; }
    const auto& getExponent() const { return part1; }
    
    auto& getE() { return part1; }
    const auto& getE() const { return part1; }
    
    auto& getN() { return part2; }
    const auto& getN() const { return part2; }
};

struct AccessiblePrivateKey : juce::RSAKey
{
    AccessiblePrivateKey() = default;
    //https://myarch.com/public-private-key-file-formats
    AccessiblePrivateKey(const juce::BigInteger& n_bi_, //modulus
                         const juce::BigInteger& e_bi_, //public exponent
                         const juce::BigInteger& d_bi_, //private exponent
                         const juce::BigInteger& p_bi_, //prime1
                         const juce::BigInteger& q_bi_, //prime2
                         const juce::BigInteger& dP_bi_, //exponent1: d mod (p-1)
                         const juce::BigInteger& dQ_bi_, //exponent2: d mod (q-1)
                         const juce::BigInteger& qInv_bi_) //coeff: (q^-1) mod p
    {
        /*
         publicKey.part1 = e;
         publicKey.part2 = n;

         privateKey.part1 = d;
         privateKey.part2 = n;
         */
        part1 = d_bi_;
        part2 = n_bi_;
        
        n_bi = n_bi_;
        e_bi = e_bi_;
        d_bi = d_bi_;
        p_bi = p_bi_;
        q_bi = q_bi_;
        dP_bi = dP_bi_;
        dQ_bi = dQ_bi_;
        qInv_bi = qInv_bi_;
    }
    
    auto& getN() { return n_bi; }
    const auto& getN() const { return n_bi; }
    
    auto& getE() { return e_bi; }
    const auto& getE() const { return e_bi; }
    
    auto& getD() { return d_bi; }
    const auto& getD() const { return d_bi; }
    
    auto& getP() { return p_bi; }
    const auto& getP() const { return p_bi; }
    
    auto& getQ() { return q_bi; }
    const auto& getQ() const { return q_bi; }
    
    auto& get_dP() { return dP_bi; }
    const auto& get_dP() const { return dP_bi; }
    
    auto& get_dQ() { return dQ_bi; }
    const auto& get_dQ() const { return dQ_bi; }
    
    auto& getQInv() { return qInv_bi; }
    const auto& getQInv() const { return qInv_bi; }
    
    AccessiblePublicKey getDerivedPublicKey() const
    {
        return AccessiblePublicKey(n_bi, e_bi);
    }
    
    friend bool operator==(const AccessiblePrivateKey& lhs,
                           const AccessiblePrivateKey& rhs)
    {
        return
        lhs.n_bi == rhs.n_bi &&
        lhs.e_bi == rhs.e_bi &&
        lhs.d_bi == rhs.d_bi &&
        lhs.p_bi == rhs.p_bi &&
        lhs.q_bi == rhs.q_bi &&
        lhs.dP_bi == rhs.dP_bi &&
        lhs.dQ_bi == rhs.dQ_bi &&
        lhs.qInv_bi == rhs.qInv_bi;
    }
    friend bool operator !=(const AccessiblePrivateKey& lhs,
                            const AccessiblePrivateKey& rhs)
    {
        return !(lhs == rhs);
    }
private:
    juce::BigInteger n_bi;
    juce::BigInteger e_bi;
    juce::BigInteger d_bi;
    juce::BigInteger p_bi;
    juce::BigInteger q_bi;
    juce::BigInteger dP_bi;
    juce::BigInteger dQ_bi;
    juce::BigInteger qInv_bi;
};

inline juce::BigInteger findBestCommonDivisor (const juce::BigInteger& p, const juce::BigInteger& q)
{
    // try 3, 5, 9, 17, etc first because these only contain 2 bits and so
    // are fast to divide + multiply
    for (int i = 2; i <= 65536; i *= 2)
    {
        const juce::BigInteger e (1 + i);

        if (e.findGreatestCommonDivisor (p).isOne() && e.findGreatestCommonDivisor (q).isOne())
            return e;
    }

    juce::BigInteger e (4);

    while (! (e.findGreatestCommonDivisor (p).isOne() && e.findGreatestCommonDivisor (q).isOne()))
        ++e;

    return e;
}

inline auto createAccessibleKeyPair(const int numBits, const int* randomSeeds, const int numRandomSeeds) -> std::tuple<AccessiblePublicKey, AccessiblePrivateKey>
{
    using namespace juce;
    
    /*
     this is a copy of juce::RSA::createKeyPair internals
     */
    jassert (numBits > 16); // not much point using less than this..
    jassert (numRandomSeeds == 0 || numRandomSeeds >= 2); // you need to provide plenty of seeds here!

    BigInteger p (Primes::createProbablePrime (numBits / 2, 30, randomSeeds, numRandomSeeds / 2));
    BigInteger q (Primes::createProbablePrime (numBits - numBits / 2, 30, randomSeeds == nullptr ? nullptr : (randomSeeds + numRandomSeeds / 2), numRandomSeeds - numRandomSeeds / 2));

    const BigInteger n (p * q);
    auto pMinus1 = --p;
    auto qMinus1 = --q;
    const BigInteger m (pMinus1 * qMinus1);
    const BigInteger e (findBestCommonDivisor (p, q));

    BigInteger d (e);
    d.inverseModulo (m);
    
    
    /*
     juce::RSA::createKeyPair does not compute dP, dQ, and qInv, which are needed to correctly generate an ASN.1 RSA Key in PEM format.
     
     dP, dQ, and qInv are computed as shown in this image:
     https://en.wikipedia.org/wiki/RSA_(cryptosystem)#:~:text=The%20following%20values%20are%20precomputed%20and%20stored%20as%20part%20of%20the%20private%20key%3A
     note that p-1 and q-1 were computed above: (--p * --q);
     */
    BigInteger dP;
    dP = d % (pMinus1);
    
    BigInteger dQ;
    dQ = d % (qMinus1);
    
    BigInteger qInv ( q );
    qInv.inverseModulo(p); //this is the juce way of computing (q^-1) mod p
    
    auto privateKey = AccessiblePrivateKey(n,
                                      e,
                                      d,
                                      p,
                                      q,
                                      dP, //private key exponent1
                                      dQ, //private key exponent2
                                      qInv); //private key coefficient
    
    auto publicKey = privateKey.getDerivedPublicKey();
    
    return std::make_tuple(publicKey, privateKey);
}
