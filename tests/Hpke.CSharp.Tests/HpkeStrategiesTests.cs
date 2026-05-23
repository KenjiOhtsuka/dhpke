using System;
using Xunit;
using Hpke.CSharp;
using Hpke.Core;

namespace Hpke.CSharp.Tests
{
    public class HpkeStrategiesTests
    {
        [Fact]
        public void CustomStrategies_RoundTrip_BaseMode()
        {
            // Use C# strategies that delegate to core deterministic helpers to be test-friendly
            KemEncapsulateDelegate kemEncap = (recipientPublicKey) =>
            {
                var pair = Crypto.generateEcdhP256KeyPair();
                var epk = pair.Item2;
                var shared = Crypto.deriveSharedSecret(pair.Item1, recipientPublicKey);
                return (epk, shared);
            };

            KemDecapsulateDelegate kemDecap = (recipientPrivateKey, encappedKey) =>
            {
                return Crypto.deriveSharedSecret(recipientPrivateKey, encappedKey);
            };

            KdfExtractDelegate kdfExtract = (salt, ikm) => Crypto.hkdfExtract(salt, ikm);
            KdfExpandDelegate kdfExpand = (prk, info, length) => Crypto.hkdfExpand(prk, info, length);
            AeadEncryptDelegate aeadEnc = (key, nonce, aad, pt) => Crypto.aesGcmEncrypt(key, nonce, aad, pt);
            AeadDecryptDelegate aeadDec = (key, nonce, aad, ct) => {
                var maybe = Crypto.aesGcmDecrypt(key, nonce, aad, ct);
                return maybe == null ? null : maybe.Value;
            };

            var strategies = new HpkeStrategies
            {
                KemEncapsulate = kemEncap,
                KemDecapsulate = kemDecap,
                KdfExtract = kdfExtract,
                KdfExpand = kdfExpand,
                AeadEncrypt = aeadEnc,
                AeadDecrypt = aeadDec,
                KeySize = 16,
                NonceSize = 12,
                TagSize = 16,
            };

            var recipient = HpkeKeyPair.Generate();
            var cfgSender = HpkeConfig.ForBaseSender(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PublicKey, strategies);
            var sealedValue = Hpke.Encrypt(cfgSender, new byte[] { 9, 8, 7 });

            var cfgRecipient = HpkeConfig.ForBaseRecipient(HpkeSuite.DhKemP256_HkdfSha256_AesGcm128, recipient.PrivateKey, sealedValue.EncappedKey, strategies);
            var decrypted = Hpke.Decrypt(cfgRecipient, sealedValue);

            Assert.Equal(new byte[] { 9, 8, 7 }, decrypted);
        }
    }
}
