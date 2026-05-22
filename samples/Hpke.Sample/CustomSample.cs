using Hpke.CSharp;

internal static class CustomSample
{
    public static void Run(HpkeSuite suite)
    {
        var recipient = HpkeKeyPair.Generate();
        var plaintext = SampleHelpers.Utf8.GetBytes("custom delegates from C#");

        var strategies = new HpkeStrategies
        {
            KemEncapsulate = (byte[] recipientPublicKey) =>
            {
                var (esk, epk) = Hpke.Core.Crypto.generateEcdhP256KeyPair();
                var shared = Hpke.Core.Crypto.deriveSharedSecret(esk, recipientPublicKey);
                return (epk, shared);
            },
            KemDecapsulate = (byte[] recipientPrivateKey, byte[] encappedKey) => Hpke.Core.Crypto.deriveSharedSecret(recipientPrivateKey, encappedKey),
            KdfExtract = (byte[]? salt, byte[] ikm) => Hpke.Core.Crypto.hkdfExtract(salt, ikm),
            KdfExpand = (byte[] prk, byte[] info, int length) => Hpke.Core.Crypto.hkdfExpand(prk, info, length),
            AeadEncrypt = (byte[] key, byte[] nonce, byte[] aad, byte[] pt) => Hpke.Core.Crypto.aesGcmEncrypt(key, nonce, aad, pt),
            AeadDecrypt = (byte[] key, byte[] nonce, byte[] aad, byte[] ct) =>
            {
                var maybe = Hpke.Core.Crypto.aesGcmDecrypt(key, nonce, aad, ct);
                return maybe == null ? null : maybe.Value;
            },
            KeySize = 16,
            NonceSize = 12,
            TagSize = 16
        };

        var sender = HpkeSenderContext.Setup(HpkeConfig.ForBaseSender(suite, recipient.PublicKey, strategies));
        var sealedValue = sender.Seal(plaintext);
        var recipientCtx = HpkeRecipientContext.Setup(HpkeConfig.ForBaseRecipient(suite, recipient.PrivateKey, sealedValue.EncappedKey, strategies));
        var opened = recipientCtx.Open(sealedValue.Ciphertext);

        SampleHelpers.PrintRoundtrip("Custom", plaintext, opened);
    }
}
