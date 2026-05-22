using Hpke.CSharp;

internal static class AuthSample
{
    public static void Run(HpkeSuite suite)
    {
        var recipient = HpkeKeyPair.Generate();
        var sender = HpkeKeyPair.Generate();
        var plaintext = SampleHelpers.Utf8.GetBytes("auth mode from C#");

        var senderContext = HpkeSenderContext.Setup(suite, recipient.PublicKey, sender.PrivateKey);
        var sealedValue = senderContext.Seal(plaintext);
        var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, sender.PublicKey);
        var openResult = recipientContext.Open(sealedValue.Ciphertext);

        SampleHelpers.PrintRoundtrip("Auth", plaintext, openResult);
    }
}
