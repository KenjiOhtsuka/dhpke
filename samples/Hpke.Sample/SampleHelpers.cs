using System;
using System.Text;

internal static class SampleHelpers
{
    public static readonly Encoding Utf8 = Encoding.UTF8;

    public static void PrintRoundtrip(string label, byte[] plaintext, byte[] opened)
    {
        Console.WriteLine($"{label}: {Utf8.GetString(plaintext)} -> {Utf8.GetString(opened)}");
    }
}
