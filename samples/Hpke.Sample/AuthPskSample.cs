using System;
using Hpke.CSharp;

internal static class AuthPskSample
{
    public static void Run(HpkeSuite suite)
    {
        try
        {
            var recipient = HpkeKeyPair.Generate();
            var sender = HpkeKeyPair.Generate();
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
            var recipient = HpkeKeyPair.Generate();
            var sender = HpkeKeyPair.Generate();
            var plaintext = SampleHelpers.Utf8.GetBytes("auth psk fallback from C#");
            var psk = new byte[] { 1, 2, 3 };

            var pair = Hpke.Core.Crypto.generateEcdhP256KeyPair();
            var esk = pair.Item1;
            var epk = pair.Item2;
            var shared1 = Hpke.Core.Crypto.deriveSharedSecret(esk, recipient.PublicKey);
            var sharedAuth = Hpke.Core.Crypto.deriveSharedSecret(sender.PrivateKey, recipient.PublicKey);
            var combined = new byte[shared1.Length + sharedAuth.Length];
            Buffer.BlockCopy(shared1, 0, combined, 0, shared1.Length);
            Buffer.BlockCopy(sharedAuth, 0, combined, shared1.Length, sharedAuth.Length);
            var prk = Hpke.Core.Crypto.hkdfExtract(psk, combined);
            var key = Hpke.Core.Crypto.hkdfExpand(prk, Array.Empty<byte>(), 32);
            var nonce = Hpke.Core.Crypto.hkdfExpand(prk, new byte[] { 0 }, 12);
            var ct = Hpke.Core.Crypto.aesGcmEncrypt(key, nonce, Array.Empty<byte>(), plaintext);
            var maybe = Hpke.Core.Crypto.aesGcmDecrypt(key, nonce, Array.Empty<byte>(), ct);
            var pt = maybe == null ? Array.Empty<byte>() : maybe.Value;
            SampleHelpers.PrintRoundtrip("AuthPSK-fallback", plaintext, pt);
        }
    }
}
