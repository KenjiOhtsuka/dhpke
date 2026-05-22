using System;
using System.Text;
using Hpke.CSharp;

internal static class Program
{
	private static readonly Encoding Utf8 = Encoding.UTF8;

	public static void Main()
	{
		var suite = HpkeSuite.DhKemP256_HkdfSha256_AesGcm128;

		try { BaseSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunBase failed: {ex.Message}"); }
		try { PskSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunPsk failed: {ex.Message}"); }
		try { AuthSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunAuth failed: {ex.Message}"); }
		try { AuthPskSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunAuthPsk failed: {ex.Message}"); }

		try { CustomSample.Run(suite); } catch (Exception ex) { Console.WriteLine($"RunCustom failed: {ex.Message}"); }
	}


}
