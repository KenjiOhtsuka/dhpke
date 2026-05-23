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
    }
}
