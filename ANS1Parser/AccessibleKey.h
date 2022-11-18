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
    AccessiblePublicKey(const juce::BigInteger& n,
                        const juce::BigInteger& e)
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
    AccessiblePrivateKey(const juce::BigInteger& n_bi_,
                         const juce::BigInteger& e_bi_,
                         const juce::BigInteger& d_bi_,
                         const juce::BigInteger& p_bi_,
                         const juce::BigInteger& q_bi_,
                         const juce::BigInteger& dP_bi_,
                         const juce::BigInteger& dQ_bi_,
                         const juce::BigInteger& qInv_bi_)
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
        return AccessiblePublicKey(e_bi, n_bi);
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
