using System;
using System.Text;
using Hpke.CSharp;

internal static class SampleHelpers
{
    public static readonly Encoding Utf8 = Encoding.UTF8;

    public static HpkeKeyPair GenerateKeyPair(HpkeSuite suite) => suite switch
    {
        HpkeSuite.DhKemP256_HkdfSha256_AesGcm128 or HpkeSuite.DhKemP256_HkdfSha256_AesGcm256 => HpkeKeyPair.Generate(HpkeKemAlgorithm.DhKemP256HkdfSha256),
        HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 or HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => HpkeKeyPair.Generate(HpkeKemAlgorithm.DhKemP384HkdfSha384),
        HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 or HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => HpkeKeyPair.Generate(HpkeKemAlgorithm.DhKemP521HkdfSha512),
        _ => throw new NotSupportedException($"Unsupported suite: {suite}")
    };

    public static void PrintRoundtrip(string label, byte[] plaintext, byte[] opened)
    {
        Console.WriteLine($"{label}: {Utf8.GetString(plaintext)} -> {Utf8.GetString(opened)}");
    }
}
