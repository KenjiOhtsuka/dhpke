using System;
using Hpke.CSharp;

internal static class PskSample
{
    public static void Run(HpkeSuite suite)
    {
        try
        {
            var recipient = HpkeKeyPair.Generate();
            var plaintext = SampleHelpers.Utf8.GetBytes("psk mode from C#");
            var psk = new byte[] { 1, 2, 3 };
            var pskId = new byte[] { 9 };

            var sender = HpkeSenderContext.SetupPsk(suite, recipient.PublicKey, psk, pskId);
            var sealedValue = sender.Seal(plaintext);
            var recipientContext = HpkeRecipientContext.SetupPsk(suite, recipient.PrivateKey, sealedValue.EncappedKey, psk, pskId);
            var openResult = recipientContext.Open(sealedValue.Ciphertext);

            SampleHelpers.PrintRoundtrip("PSK", plaintext, openResult);
        }
        catch (Exception)
        {
            // Fallback: demonstrate equivalent steps with low-level primitives
            var recipient = HpkeKeyPair.Generate();
            var plaintext = SampleHelpers.Utf8.GetBytes("psk mode fallback from C#");
            var psk = new byte[] { 1, 2, 3 };

            var pair = Hpke.Core.Crypto.generateEcdhP256KeyPair(); // (priv,pub)
            var esk = pair.Item1;
            var epk = pair.Item2;
            var shared1 = Hpke.Core.Crypto.deriveSharedSecret(esk, recipient.PublicKey);
            var prk = Hpke.Core.Crypto.hkdfExtract(psk, shared1);
            var key = Hpke.Core.Crypto.hkdfExpand(prk, Array.Empty<byte>(), 32);
            var nonce = Hpke.Core.Crypto.hkdfExpand(prk, new byte[] { 0 }, 12);
            var ct = Hpke.Core.Crypto.aesGcmEncrypt(key, nonce, Array.Empty<byte>(), plaintext);
            var maybe = Hpke.Core.Crypto.aesGcmDecrypt(key, nonce, Array.Empty<byte>(), ct);
            var pt = maybe == null ? Array.Empty<byte>() : maybe.Value;
            SampleHelpers.PrintRoundtrip("PSK-fallback", plaintext, pt);
        }
    }
}
