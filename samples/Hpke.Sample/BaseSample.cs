using Hpke.CSharp;

internal static class BaseSample
{
    public static void Run(HpkeSuite suite)
    {
        var recipient = HpkeKeyPair.Generate();
        var plaintext = SampleHelpers.Utf8.GetBytes("base mode from C#");

        var sender = HpkeSenderContext.Setup(suite, recipient.PublicKey);
        var sealedValue = sender.Seal(plaintext);
        var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey);
        var openResult = recipientContext.Open(sealedValue.Ciphertext);

        SampleHelpers.PrintRoundtrip("Base", plaintext, openResult);
    }
}
