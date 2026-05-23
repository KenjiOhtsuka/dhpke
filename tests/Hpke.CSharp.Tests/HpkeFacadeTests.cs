using System;
using Xunit;
using Hpke.CSharp;

namespace Hpke.CSharp.Tests
{
    public class HpkeFacadeTests
    {
        [Fact]
        public void SenderRecipient_RoundTrip_BaseMode()
        {
            var recipient = HpkeKeyPair.Generate();
            var plaintext = new byte[] { 1, 2, 3, 4, 5 };

            var sealedValue = HpkeSenderContext.Setup(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PublicKey).Seal(plaintext);

            var decrypted = HpkeRecipientContext.Setup(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PrivateKey, sealedValue.EncappedKey).Open(sealedValue.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void SenderRecipient_RoundTrip_BaseMode_Aes256GcmSuite()
        {
            var recipient = HpkeKeyPair.Generate();
            var plaintext = new byte[] { 7, 6, 5, 4 };

            var sealedValue = HpkeSenderContext.Setup(HpkeSuite.DhKemP256_HkdfSha256_AesGcm256, recipient.PublicKey).Seal(plaintext);

            var decrypted = HpkeRecipientContext.Setup(HpkeSuite.DhKemP256_HkdfSha256_AesGcm256, recipient.PrivateKey, sealedValue.EncappedKey).Open(sealedValue.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void SenderRecipient_RoundTrip_BaseMode_P384Suite()
        {
            var recipient = HpkeKeyPair.Generate(HpkeKemAlgorithm.DhKemP384HkdfSha384);
            var plaintext = new byte[] { 11, 12, 13 };

            var sealedValue = HpkeSenderContext.Setup(HpkeSuite.DhKemP384_HkdfSha384_AesGcm128, recipient.PublicKey).Seal(plaintext);

            var decrypted = HpkeRecipientContext.Setup(HpkeSuite.DhKemP384_HkdfSha384_AesGcm128, recipient.PrivateKey, sealedValue.EncappedKey).Open(sealedValue.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

        [Fact]
        public void SenderRecipient_RoundTrip_BaseMode_P521Suite()
        {
            var recipient = HpkeKeyPair.Generate(HpkeKemAlgorithm.DhKemP521HkdfSha512);
            var plaintext = new byte[] { 21, 22, 23, 24 };

            var sealedValue = HpkeSenderContext.Setup(HpkeSuite.DhKemP521_HkdfSha512_AesGcm256, recipient.PublicKey).Seal(plaintext);

            var decrypted = HpkeRecipientContext.Setup(HpkeSuite.DhKemP521_HkdfSha512_AesGcm256, recipient.PrivateKey, sealedValue.EncappedKey).Open(sealedValue.Ciphertext);

            Assert.Equal(plaintext, decrypted);
        }

    }
}
