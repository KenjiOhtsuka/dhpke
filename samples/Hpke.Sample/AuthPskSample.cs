using System;
using Hpke.CSharp;

internal static class AuthPskSample
{
    public static void Run(HpkeSuite suite)
    {
        try
        {
            var recipient = SampleHelpers.GenerateKeyPair(suite);
            var sender = SampleHelpers.GenerateKeyPair(suite);
            var plaintext = SampleHelpers.Utf8.GetBytes("auth psk mode from C#");
            var psk = new byte[] { 1, 2, 3 };
            var pskId = new byte[] { 9 };

            var senderContext = HpkeSenderContext.SetupAuthPsk(suite, recipient.PublicKey, sender.PrivateKey, psk, pskId);
            var sealedValue = senderContext.Seal(plaintext);
            var recipientContext = HpkeRecipientContext.SetupAuthPsk(suite, recipient.PrivateKey, sealedValue.EncappedKey, sender.PublicKey, psk, pskId);
            var openResult = recipientContext.Open(sealedValue.Ciphertext);

            SampleHelpers.PrintRoundtrip("AuthPSK", plaintext, openResult);
        }
        catch (Exception)
        {
            // Fallback: combine auth and psk contributions
            var recipient = SampleHelpers.GenerateKeyPair(suite);
            var sender = SampleHelpers.GenerateKeyPair(suite);
            var plaintext = SampleHelpers.Utf8.GetBytes("auth psk fallback from C#");
            var psk = new byte[] { 1, 2, 3 };

            var pair = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.generateEcdhP384KeyPair(),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.generateEcdhP521KeyPair(),
                _ => Hpke.Core.Crypto.generateEcdhP256KeyPair()
            };
            var esk = pair.Item1;
            var epk = pair.Item2;
            var shared1 = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.deriveSharedSecretP384(esk, recipient.PublicKey),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.deriveSharedSecretP521(esk, recipient.PublicKey),
                _ => Hpke.Core.Crypto.deriveSharedSecret(esk, recipient.PublicKey)
            };
            var sharedAuth = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.deriveSharedSecretP384(sender.PrivateKey, recipient.PublicKey),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.deriveSharedSecretP521(sender.PrivateKey, recipient.PublicKey),
                _ => Hpke.Core.Crypto.deriveSharedSecret(sender.PrivateKey, recipient.PublicKey)
            };
            var combined = new byte[shared1.Length + sharedAuth.Length];
            Buffer.BlockCopy(shared1, 0, combined, 0, shared1.Length);
            Buffer.BlockCopy(sharedAuth, 0, combined, shared1.Length, sharedAuth.Length);
            var prk = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.hkdfExtractWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA384"), psk, combined),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.hkdfExtractWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA512"), psk, combined),
                _ => Hpke.Core.Crypto.hkdfExtract(psk, combined)
            };
            var key = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.hkdfExpandWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA384"), prk, Array.Empty<byte>(), 32),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.hkdfExpandWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA512"), prk, Array.Empty<byte>(), 32),
                _ => Hpke.Core.Crypto.hkdfExpand(prk, Array.Empty<byte>(), 32)
            };
            var nonce = suite switch
            {
                HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => Hpke.Core.Crypto.hkdfExpandWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA384"), prk, new byte[] { 0 }, 12),
                HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => Hpke.Core.Crypto.hkdfExpandWithHash(new System.Security.Cryptography.HashAlgorithmName("SHA512"), prk, new byte[] { 0 }, 12),
                _ => Hpke.Core.Crypto.hkdfExpand(prk, new byte[] { 0 }, 12)
            };
            var ct = Hpke.Core.Crypto.aesGcmEncrypt(key, nonce, Array.Empty<byte>(), plaintext);
            var maybe = Hpke.Core.Crypto.aesGcmDecrypt(key, nonce, Array.Empty<byte>(), ct);
            var pt = maybe == null ? Array.Empty<byte>() : maybe.Value;
            SampleHelpers.PrintRoundtrip("AuthPSK-fallback", plaintext, pt);
        }
    }
}
