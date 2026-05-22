using System;
using System.Text;
using Hpke.CSharp;

internal static class Program
{
	private static readonly Encoding Utf8 = Encoding.UTF8;

	public static void Main()
	{
		var suite = HpkeSuite.DhKemP256_HkdfSha256_AesGcm128;

		RunBase(suite);
		RunPsk(suite);
		RunAuth(suite);
		RunAuthPsk(suite);
	}

	private static void RunBase(HpkeSuite suite)
	{
		var recipient = HpkeKeyPair.Generate();
		var plaintext = Utf8.GetBytes("base mode from C#");

		var sender = HpkeSenderContext.Setup(suite, recipient.PublicKey);
		var sealedValue = sender.Seal(plaintext);
		var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey);
		var openResult = recipientContext.Open(sealedValue.Ciphertext);

		PrintRoundtrip("Base", plaintext, openResult);
	}

	private static void RunPsk(HpkeSuite suite)
	{
		var recipient = HpkeKeyPair.Generate();
		var plaintext = Utf8.GetBytes("psk mode from C#");
		var psk = new byte[] { 1, 2, 3 };
		var pskId = new byte[] { 9 };

		var sender = HpkeSenderContext.Setup(suite, recipient.PublicKey, psk, pskId);
		var sealedValue = sender.Seal(plaintext);
		var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, psk, pskId);
		var openResult = recipientContext.Open(sealedValue.Ciphertext);

		PrintRoundtrip("PSK", plaintext, openResult);
	}

	private static void RunAuth(HpkeSuite suite)
	{
		var recipient = HpkeKeyPair.Generate();
		var sender = HpkeKeyPair.Generate();
		var plaintext = Utf8.GetBytes("auth mode from C#");

		var senderContext = HpkeSenderContext.Setup(suite, recipient.PublicKey, sender.PrivateKey);
		var sealedValue = senderContext.Seal(plaintext);
		var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, sender.PublicKey);
		var openResult = recipientContext.Open(sealedValue.Ciphertext);

		PrintRoundtrip("Auth", plaintext, openResult);
	}

	private static void RunAuthPsk(HpkeSuite suite)
	{
		var recipient = HpkeKeyPair.Generate();
		var sender = HpkeKeyPair.Generate();
		var plaintext = Utf8.GetBytes("auth psk mode from C#");
		var psk = new byte[] { 1, 2, 3 };
		var pskId = new byte[] { 9 };

		var senderContext = HpkeSenderContext.Setup(suite, recipient.PublicKey, sender.PrivateKey, psk, pskId);
		var sealedValue = senderContext.Seal(plaintext);
		var recipientContext = HpkeRecipientContext.Setup(suite, recipient.PrivateKey, sealedValue.EncappedKey, sender.PublicKey, psk, pskId);
		var openResult = recipientContext.Open(sealedValue.Ciphertext);

		PrintRoundtrip("AuthPSK", plaintext, openResult);
	}

	private static void PrintRoundtrip(string label, byte[] plaintext, byte[] opened)
	{
		Console.WriteLine($"{label}: {Utf8.GetString(plaintext)} -> {Utf8.GetString(opened)}");
	}

}
