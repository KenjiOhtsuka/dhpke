using System;
using System.Collections.Generic;
using Xunit;
using Hpke.CSharp;
using Hpke.Core;

namespace Hpke.CSharp.Tests
{
    public class HpkeStrategiesExtraTests
    {
        [Fact]
        public void PskMode_RoundTrip()
        {
            var recipient = HpkeKeyPair.Generate();
            var psk = new byte[] { 1, 2, 3 };
            var pskId = new byte[] { 9 };

            var sealedValue = HpkeSenderContext.SetupPsk(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PublicKey, psk, pskId).Seal(new byte[] { 10, 11 });
            var decrypted = HpkeRecipientContext.SetupPsk(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PrivateKey, sealedValue.EncappedKey, psk, pskId).Open(sealedValue.Ciphertext);

            Assert.Equal(new byte[] { 10, 11 }, decrypted);
        }

        [Fact]
        public void PartialStrategies_KdfExpand_RecordedLengths()
        {
            var lengths = new List<int>();
            KdfExpandDelegate kdfExpand = (prk, info, length) =>
            {
                lengths.Add(length);
                return Crypto.hkdfExpand(prk, info, length);
            };

            var strategies = new HpkeStrategies
            {
                KdfExpand = kdfExpand,
                KeySize = 16,
                NonceSize = 12,
            };

            var recipient = HpkeKeyPair.Generate();
            var cfgSender = HpkeConfig.ForBaseSender(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PublicKey, strategies: strategies);
            var sealedValue = Hpke.Encrypt(cfgSender, new byte[] { 4, 5, 6 });

            var cfgRecipient = HpkeConfig.ForBaseRecipient(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PrivateKey, sealedValue.EncappedKey, strategies: strategies);
            var decrypted = Hpke.Decrypt(cfgRecipient, sealedValue);

            Assert.Equal(new byte[] { 4, 5, 6 }, decrypted);

            // kdfExpand should have been called for key and nonce (sender + recipient)
            Assert.Contains(16, lengths);
            Assert.Contains(12, lengths);
        }

        [Fact]
        public void DelegateException_Propagates()
        {
            AeadEncryptDelegate badEnc = (key, nonce, aad, pt) => throw new InvalidOperationException("delegate boom");
            var strategies = new HpkeStrategies { AeadEncrypt = badEnc };
            var recipient = HpkeKeyPair.Generate();

            var cfg = HpkeConfig.ForBaseSender(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PublicKey, strategies: strategies);

            Assert.Throws<InvalidOperationException>(() => Hpke.Encrypt(cfg, new byte[] { 1 }));
        }
    }
}
