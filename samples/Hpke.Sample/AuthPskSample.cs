using Hpke.CSharp;

internal static class AuthPskSample
{
    public static void Run(HpkeSuite suite)
    {
        var recipient = HpkeKeyPair.Generate();
        var sender = HpkeKeyPair.Generate();
        var plaintext = SampleHelpers.Utf8.GetBytes("auth psk mode from C#");
        var psk = new byte[] { 1, 2, 3 };
        var pskId = new byte[] { 9 };

        var senderContext = HpkeSenderContext.Setup(suite, recipient.PublicKey, sender.PrivateKey, psk, pskId);
        var sealedValue = senderContext.Seal(plaintext);
        var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, sender.PublicKey, psk, pskId);
        var openResult = recipientContext.Open(sealedValue.Ciphertext);

        SampleHelpers.PrintRoundtrip("AuthPSK", plaintext, openResult);
    }
}
