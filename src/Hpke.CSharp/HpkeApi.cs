using System;
using System.Security.Cryptography;
using Hpke.Core;
using Microsoft.FSharp.Core;

namespace Hpke.CSharp;

public enum HpkeSuite
{
    DhKemP256_HkdfSha256_AesGcm128,
}

public enum HpkeKemAlgorithm
{
    DhKemP256HkdfSha256,
    DhKemP384HkdfSha384,
    DhKemP521HkdfSha512,
}

public enum HpkeKdfAlgorithm
{
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

public enum HpkeAeadAlgorithm
{
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

public enum HpkeModeKind
{
    Base,
    Psk,
    Auth,
    AuthPsk,
}

public sealed class HpkeKeyPair
{
    public HpkeKeyPair(byte[] privateKey, byte[] publicKey)
    {
        PrivateKey = RequireBytes(privateKey, nameof(privateKey));
        PublicKey = RequireBytes(publicKey, nameof(publicKey));
    }

    public byte[] PrivateKey { get; }

    public byte[] PublicKey { get; }

    public static HpkeKeyPair Generate()
    {
        var (privateKey, publicKey) = Crypto.generateEcdhP256KeyPair();
        return new HpkeKeyPair(privateKey, publicKey);
    }

    private static byte[] RequireBytes(byte[] value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        return value;
    }
}

public sealed class HpkeSealedValue
{
    public HpkeSealedValue(byte[] encappedKey, byte[] ciphertext)
    {
        EncappedKey = RequireBytes(encappedKey, nameof(encappedKey));
        Ciphertext = RequireBytes(ciphertext, nameof(ciphertext));
    }

    public byte[] EncappedKey { get; }

    public byte[] Ciphertext { get; }

    private static byte[] RequireBytes(byte[] value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        return value;
    }
}

public sealed class HpkeConfig
{
    private readonly HpkeKemAlgorithm kem;
    private readonly HpkeKdfAlgorithm kdf;
    private readonly HpkeAeadAlgorithm aead;

    private HpkeConfig(
        HpkeModeKind mode,
        HpkeSuite suite,
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[]? recipientPublicKey,
        byte[]? recipientPrivateKey,
        byte[]? senderPrivateKey,
        byte[]? senderPublicKey,
        byte[] info,
        byte[]? psk,
        byte[]? pskId,
        byte[]? encappedKey)
    {
        Mode = mode;
        Suite = suite;
        this.kem = kem;
        this.kdf = kdf;
        this.aead = aead;
        RecipientPublicKey = recipientPublicKey;
        RecipientPrivateKey = recipientPrivateKey;
        SenderPrivateKey = senderPrivateKey;
        SenderPublicKey = senderPublicKey;
        Info = info;
        Psk = psk;
        PskId = pskId;
        EncappedKey = encappedKey;
    }

    public HpkeModeKind Mode { get; }

    public HpkeSuite Suite { get; }

    public HpkeKemAlgorithm Kem => kem;

    public HpkeKdfAlgorithm Kdf => kdf;

    public HpkeAeadAlgorithm Aead => aead;

    public byte[]? RecipientPublicKey { get; }

    public byte[]? RecipientPrivateKey { get; }

    public byte[]? SenderPrivateKey { get; }

    public byte[]? SenderPublicKey { get; }

    public byte[] Info { get; }

    public byte[]? Psk { get; }

    public byte[]? PskId { get; }

    public byte[]? EncappedKey { get; }

    public static HpkeConfig ForBaseSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[]? info = null)
        => new(HpkeModeKind.Base, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), null, null, null);

    public static HpkeConfig ForBaseRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[]? info = null)
        => new(HpkeModeKind.Base, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForPskSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.Psk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null);

    public static HpkeConfig ForPskRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.Psk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForAuthSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] senderPrivateKey,
        byte[]? info = null)
        => new(HpkeModeKind.Auth, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), null, null, null);

    public static HpkeConfig ForAuthRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[] senderPublicKey,
        byte[]? info = null)
        => new(HpkeModeKind.Auth, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForAuthPskSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] senderPrivateKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null);

    public static HpkeConfig ForAuthPskRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[] senderPublicKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForBaseSender(HpkeSuite suite, byte[] recipientPublicKey, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), null, null, null);

    public static HpkeConfig ForBaseRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForPskSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.Psk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null);

    public static HpkeConfig ForPskRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.Psk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForAuthSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[]? info = null)
        => new(HpkeModeKind.Auth, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), null, null, null);

    public static HpkeConfig ForAuthRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[]? info = null)
        => new(HpkeModeKind.Auth, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)));

    public static HpkeConfig ForAuthPskSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null);

    public static HpkeConfig ForAuthPskRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)));

    private static byte[] Normalize(byte[]? value) => value is null ? Array.Empty<byte>() : value;

    private static byte[] RequireBytes(byte[] value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        return value;
    }

    private static HpkeSuite DefaultSuiteIfSupported(HpkeKemAlgorithm kem, HpkeKdfAlgorithm kdf, HpkeAeadAlgorithm aead)
    {
        if (kem == HpkeKemAlgorithm.DhKemP256HkdfSha256 && kdf == HpkeKdfAlgorithm.HkdfSha256 && aead == HpkeAeadAlgorithm.Aes128Gcm)
        {
            return HpkeSuite.DhKemP256_HkdfSha256_AesGcm128;
        }

        throw new NotSupportedException($"Unsupported algorithm combination: {kem}/{kdf}/{aead}");
    }
}

public sealed class HpkeSenderContext
{
    private readonly HpkeConfig config;

    private HpkeSenderContext(HpkeConfig config)
    {
        this.config = config;
    }

    public static HpkeSenderContext Setup(HpkeConfig config) => new(config ?? throw new ArgumentNullException(nameof(config)));

    public static HpkeSenderContext Setup(HpkeSuite suite, byte[] recipientPublicKey, byte[]? info = null)
        => Setup(HpkeConfig.ForBaseSender(suite, recipientPublicKey, info));

    public static HpkeSenderContext Setup(HpkeSuite suite, byte[] recipientPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForPskSender(suite, recipientPublicKey, psk, pskId, info));

    public static HpkeSenderContext Setup(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthSender(suite, recipientPublicKey, senderPrivateKey, info));

    public static HpkeSenderContext Setup(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthPskSender(suite, recipientPublicKey, senderPrivateKey, psk, pskId, info));

    public HpkeSealedValue Seal(byte[] plaintext, byte[]? aad = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        return Hpke.Seal(config, plaintext, aad ?? Array.Empty<byte>());
    }
}

public sealed class HpkeRecipientContext
{
    private readonly HpkeConfig config;

    private HpkeRecipientContext(HpkeConfig config)
    {
        this.config = config;
    }

    public static HpkeRecipientContext Setup(HpkeConfig config) => new(config ?? throw new ArgumentNullException(nameof(config)));

    public static HpkeRecipientContext Setup(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[]? info = null)
        => Setup(HpkeConfig.ForBaseRecipient(suite, recipientPrivateKey, encappedKey, info));

    public static HpkeRecipientContext Setup(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForPskRecipient(suite, recipientPrivateKey, encappedKey, psk, pskId, info));

    public static HpkeRecipientContext Setup(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthRecipient(suite, recipientPrivateKey, encappedKey, senderPublicKey, info));

    public static HpkeRecipientContext Setup(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthPskRecipient(suite, recipientPrivateKey, encappedKey, senderPublicKey, psk, pskId, info));

    public byte[] Open(byte[] ciphertext, byte[]? aad = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);

        return Hpke.Open(config, ciphertext, aad ?? Array.Empty<byte>());
    }
}

public static class Hpke
{
    public static HpkeKeyPair GenerateKeyPair() => HpkeKeyPair.Generate();

    public static HpkeSealedValue Encrypt(HpkeConfig config, byte[] plaintext, byte[]? aad = null)
        => HpkeSenderContext.Setup(config).Seal(plaintext, aad);

    public static byte[] Decrypt(HpkeConfig config, HpkeSealedValue sealedValue, byte[]? aad = null)
    {
        ArgumentNullException.ThrowIfNull(sealedValue);
        return HpkeRecipientContext.Setup(config).Open(sealedValue.Ciphertext, aad);
    }

    internal static HpkeSealedValue Seal(HpkeConfig config, byte[] plaintext, byte[] aad)
    {
        var result = config.Mode switch
        {
            HpkeModeKind.Base => Base.Seal(CreateBaseSealRequest(config, plaintext, aad)),
            HpkeModeKind.Psk => Psk.Seal(CreatePskSealRequest(config, plaintext, aad)),
            HpkeModeKind.Auth => Auth.Seal(CreateAuthSealRequest(config, plaintext, aad)),
            HpkeModeKind.AuthPsk => AuthPsk.Seal(CreateAuthPskSealRequest(config, plaintext, aad)),
            _ => throw new ArgumentOutOfRangeException(),
        };

        return ToSealedValue(result, nameof(Seal));
    }

    internal static byte[] Open(HpkeConfig config, byte[] ciphertext, byte[] aad)
    {
        var result = config.Mode switch
        {
            HpkeModeKind.Base => Base.Open(CreateBaseOpenRequest(config, ciphertext, aad)),
            HpkeModeKind.Psk => Psk.Open(CreatePskOpenRequest(config, ciphertext, aad)),
            HpkeModeKind.Auth => Auth.Open(CreateAuthOpenRequest(config, ciphertext, aad)),
            HpkeModeKind.AuthPsk => AuthPsk.Open(CreateAuthPskOpenRequest(config, ciphertext, aad)),
            _ => throw new ArgumentOutOfRangeException(),
        };

        return ToPlaintext(result, nameof(Open));
    }

    private static BaseSealRequest CreateBaseSealRequest(HpkeConfig config, byte[] plaintext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPublicKey, nameof(config.RecipientPublicKey)), config.Info, aad, plaintext);

    private static BaseOpenRequest CreateBaseOpenRequest(HpkeConfig config, byte[] ciphertext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPrivateKey, nameof(config.RecipientPrivateKey)), Require(config.EncappedKey, nameof(config.EncappedKey)), config.Info, aad, ciphertext);

    private static PskSealRequest CreatePskSealRequest(HpkeConfig config, byte[] plaintext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPublicKey, nameof(config.RecipientPublicKey)), Require(config.Psk, nameof(config.Psk)), Require(config.PskId, nameof(config.PskId)), config.Info, aad, plaintext);

    private static PskOpenRequest CreatePskOpenRequest(HpkeConfig config, byte[] ciphertext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPrivateKey, nameof(config.RecipientPrivateKey)), Require(config.EncappedKey, nameof(config.EncappedKey)), Require(config.Psk, nameof(config.Psk)), Require(config.PskId, nameof(config.PskId)), config.Info, aad, ciphertext);

    private static AuthSealRequest CreateAuthSealRequest(HpkeConfig config, byte[] plaintext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPublicKey, nameof(config.RecipientPublicKey)), Require(config.SenderPrivateKey, nameof(config.SenderPrivateKey)), config.Info, aad, plaintext);

    private static AuthOpenRequest CreateAuthOpenRequest(HpkeConfig config, byte[] ciphertext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPrivateKey, nameof(config.RecipientPrivateKey)), Require(config.SenderPublicKey, nameof(config.SenderPublicKey)), Require(config.EncappedKey, nameof(config.EncappedKey)), config.Info, aad, ciphertext);

    private static AuthPskSealRequest CreateAuthPskSealRequest(HpkeConfig config, byte[] plaintext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPublicKey, nameof(config.RecipientPublicKey)), Require(config.SenderPrivateKey, nameof(config.SenderPrivateKey)), Require(config.Psk, nameof(config.Psk)), Require(config.PskId, nameof(config.PskId)), config.Info, aad, plaintext);

    private static AuthPskOpenRequest CreateAuthPskOpenRequest(HpkeConfig config, byte[] ciphertext, byte[] aad)
        => new(ToCoreSuite(config.Suite), Require(config.RecipientPrivateKey, nameof(config.RecipientPrivateKey)), Require(config.SenderPublicKey, nameof(config.SenderPublicKey)), Require(config.EncappedKey, nameof(config.EncappedKey)), Require(config.Psk, nameof(config.Psk)), Require(config.PskId, nameof(config.PskId)), config.Info, aad, ciphertext);

    private static HpkeSealedValue ToSealedValue(FSharpResult<BaseSealResult, HpkeError> result, string operation)
    {
        var sealedResult = Unwrap(result, operation);
        return new HpkeSealedValue(sealedResult.EncappedKey, sealedResult.Ciphertext);
    }

    private static byte[] ToPlaintext(FSharpResult<byte[], HpkeError> result, string operation)
        => Unwrap(result, operation);

    private static T Unwrap<T>(FSharpResult<T, HpkeError> result, string operation)
    {
        if (result.IsOk)
        {
            return result.ResultValue;
        }

        throw new CryptographicException($"{operation} failed: {result.ErrorValue}");
    }

    private static global::Hpke.Core.HpkeSuite ToCoreSuite(HpkeSuite suite) => suite switch
    {
        HpkeSuite.DhKemP256_HkdfSha256_AesGcm128 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP256HkdfSha256,
            global::Hpke.Core.KdfAlgorithm.HkdfSha256,
            global::Hpke.Core.AeadAlgorithm.Aes128Gcm),
        _ => throw new NotSupportedException($"Unsupported suite: {suite}"),
    };

    private static byte[] Require(byte[]? value, string name)
        => value ?? throw new ArgumentNullException(name);
}
