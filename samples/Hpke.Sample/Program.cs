using System;
using System.Text;
using Hpke.CSharp;

internal static class Program
{
	private static readonly Encoding Utf8 = Encoding.UTF8;

	public static void Main()
	{
		var baseSuites = new[]
		{
			HpkeSuite.DhKemP256_HkdfSha256_AesGcm128,
			HpkeSuite.DhKemP384_HkdfSha384_AesGcm128,
			HpkeSuite.DhKemP521_HkdfSha512_AesGcm256,
		};

		foreach (var suite in baseSuites)
		{
			try { BaseSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunBase[{suite}] failed: {ex.Message}"); }
		}

		var modeSuite = HpkeSuite.DhKemP256_HkdfSha256_AesGcm128;

		try { PskSample.Run(modeSuite); } catch (Exception ex) { Console.WriteLine($"RunPsk failed: {ex.Message}"); }
		try { AuthSample.Run(modeSuite); } catch (Exception ex) { Console.WriteLine($"RunAuth failed: {ex.Message}"); }
		try { AuthPskSample.Run(modeSuite); } catch (Exception ex) { Console.WriteLine($"RunAuthPsk failed: {ex.Message}"); }

		try { CustomSample.Run(modeSuite); } catch (Exception ex) { Console.WriteLine($"RunCustom failed: {ex.Message}"); }
	}


}
