using System;
using System.Text;
using Hpke.Core;

internal static class Program
{
	private static readonly Encoding Utf8 = Encoding.UTF8;

	public static void Main()
	{
		var suite = Suites.Default;

		RunBase(suite);
		RunPsk(suite);
		RunAuth(suite);
		RunAuthPsk(suite);
	}

	private static void RunBase(HpkeSuite suite)
	{
		var (recipientSk, recipientPk) = Crypto.generateEcdhP256KeyPair();
		var plaintext = Utf8.GetBytes("base mode from C#");

		var sealResult = Base.Seal(new BaseSealRequest(suite, recipientPk, Array.Empty<byte>(), Array.Empty<byte>(), plaintext));

		var sealedValue = RequireOk(sealResult, "Base seal");
		var openResult = Base.Open(new BaseOpenRequest(suite, recipientSk, sealedValue.EncappedKey, Array.Empty<byte>(), Array.Empty<byte>(), sealedValue.Ciphertext));

		PrintRoundtrip("Base", plaintext, RequireOk(openResult, "Base open"));
	}

	private static void RunPsk(HpkeSuite suite)
	{
		var (recipientSk, recipientPk) = Crypto.generateEcdhP256KeyPair();
		var plaintext = Utf8.GetBytes("psk mode from C#");
		var psk = new byte[] { 1, 2, 3 };
		var pskId = new byte[] { 9 };

		var sealResult = Psk.Seal(new PskSealRequest(suite, recipientPk, psk, pskId, Array.Empty<byte>(), Array.Empty<byte>(), plaintext));

		var sealedValue = RequireOk(sealResult, "PSK seal");
		var openResult = Psk.Open(new PskOpenRequest(suite, recipientSk, sealedValue.EncappedKey, psk, pskId, Array.Empty<byte>(), Array.Empty<byte>(), sealedValue.Ciphertext));

		PrintRoundtrip("PSK", plaintext, RequireOk(openResult, "PSK open"));
	}

	private static void RunAuth(HpkeSuite suite)
	{
		var (recipientSk, recipientPk) = Crypto.generateEcdhP256KeyPair();
		var (senderSk, senderPk) = Crypto.generateEcdhP256KeyPair();
		var plaintext = Utf8.GetBytes("auth mode from C#");

		var sealResult = Auth.Seal(new AuthSealRequest(suite, recipientPk, senderSk, Array.Empty<byte>(), Array.Empty<byte>(), plaintext));

		var sealedValue = RequireOk(sealResult, "Auth seal");
		var openResult = Auth.Open(new AuthOpenRequest(suite, recipientSk, senderPk, sealedValue.EncappedKey, Array.Empty<byte>(), Array.Empty<byte>(), sealedValue.Ciphertext));

		PrintRoundtrip("Auth", plaintext, RequireOk(openResult, "Auth open"));
	}

	private static void RunAuthPsk(HpkeSuite suite)
	{
		var (recipientSk, recipientPk) = Crypto.generateEcdhP256KeyPair();
		var (senderSk, senderPk) = Crypto.generateEcdhP256KeyPair();
		var plaintext = Utf8.GetBytes("auth psk mode from C#");
		var psk = new byte[] { 1, 2, 3 };
		var pskId = new byte[] { 9 };

		var sealResult = AuthPsk.Seal(new AuthPskSealRequest(suite, recipientPk, senderSk, psk, pskId, Array.Empty<byte>(), Array.Empty<byte>(), plaintext));

		var sealedValue = RequireOk(sealResult, "AuthPSK seal");
		var openResult = AuthPsk.Open(new AuthPskOpenRequest(suite, recipientSk, senderPk, sealedValue.EncappedKey, psk, pskId, Array.Empty<byte>(), Array.Empty<byte>(), sealedValue.Ciphertext));

		PrintRoundtrip("AuthPSK", plaintext, RequireOk(openResult, "AuthPSK open"));
	}

	private static void PrintRoundtrip(string label, byte[] plaintext, byte[] opened)
	{
		Console.WriteLine($"{label}: {Utf8.GetString(plaintext)} -> {Utf8.GetString(opened)}");
	}

	private static T RequireOk<T, TError>(Microsoft.FSharp.Core.FSharpResult<T, TError> result, string stage)
	{
		if (result.IsOk)
		{
			return result.ResultValue;
		}

		throw new InvalidOperationException($"{stage} failed: {result.ErrorValue}");
	}
}
