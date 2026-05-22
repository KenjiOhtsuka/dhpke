using Hpke.CSharp;

internal static class PskSample
{
    public static void Run(HpkeSuite suite)
    {
        var recipient = HpkeKeyPair.Generate();
        var plaintext = SampleHelpers.Utf8.GetBytes("psk mode from C#");
        var psk = new byte[] { 1, 2, 3 };
        var pskId = new byte[] { 9 };

        var sender = HpkeSenderContext.Setup(suite, recipient.PublicKey, psk, pskId);
        var sealedValue = sender.Seal(plaintext);
        var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, psk, pskId);
        var openResult = recipientContext.Open(sealedValue.Ciphertext);

        SampleHelpers.PrintRoundtrip("PSK", plaintext, openResult);
    }
}
