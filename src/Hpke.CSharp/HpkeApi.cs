using System;
using System.Security.Cryptography;
using Hpke.Core;
using Microsoft.FSharp.Core;

namespace Hpke.CSharp;

public enum HpkeSuite
{
    DhKemP256_HkdfSha256_AesGcm128,
    DhKemP256_HkdfSha256_AesGcm256,
    DhKemX25519_HkdfSha256_AesGcm128,
    DhKemX25519_HkdfSha256_AesGcm256,
    DhKemP384_HkdfSha384_AesGcm128,
    DhKemP384_HkdfSha384_AesGcm256,
    DhKemP521_HkdfSha512_AesGcm128,
    DhKemP521_HkdfSha512_AesGcm256,
}

public enum HpkeKemAlgorithm
{
    DhKemP256HkdfSha256,
    DhKemX25519HkdfSha256,
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
        => Generate(HpkeKemAlgorithm.DhKemP256HkdfSha256);

    public static HpkeKeyPair Generate(HpkeKemAlgorithm kem)
    {
        var (privateKey, publicKey) = kem switch
        {
            HpkeKemAlgorithm.DhKemP256HkdfSha256 => Crypto.generateEcdhP256KeyPair(),
            HpkeKemAlgorithm.DhKemX25519HkdfSha256 => Crypto.generateEcdhX25519KeyPair(),
            HpkeKemAlgorithm.DhKemP384HkdfSha384 => Crypto.generateEcdhP384KeyPair(),
            HpkeKemAlgorithm.DhKemP521HkdfSha512 => Crypto.generateEcdhP521KeyPair(),
            _ => throw new NotSupportedException($"Unsupported KEM for key generation: {kem}")
        };
        return new HpkeKeyPair(privateKey, publicKey);
    }

    private static byte[] RequireBytes(byte[] value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        return value;
    }
}

public delegate (byte[] EncappedKey, byte[] Shared) KemEncapsulateDelegate(byte[] recipientPublicKey);
public delegate byte[] KemDecapsulateDelegate(byte[] recipientPrivateKey, byte[] encappedKey);
public delegate byte[] KdfExtractDelegate(byte[]? salt, byte[] ikm);
public delegate byte[] KdfExpandDelegate(byte[] prk, byte[] info, int length);
public delegate byte[] AeadEncryptDelegate(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext);
public delegate byte[]? AeadDecryptDelegate(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext);

public sealed class HpkeStrategies
{
    public KemEncapsulateDelegate? KemEncapsulate { get; init; }
    public KemDecapsulateDelegate? KemDecapsulate { get; init; }
    public KdfExtractDelegate? KdfExtract { get; init; }
    public KdfExpandDelegate? KdfExpand { get; init; }
    public AeadEncryptDelegate? AeadEncrypt { get; init; }
    public AeadDecryptDelegate? AeadDecrypt { get; init; }
    public int KeySize { get; init; } = 16;
    public int NonceSize { get; init; } = 12;
    public int TagSize { get; init; } = 16;
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

    // New constructor accepting optional C# strategies for custom algorithms
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
        byte[]? encappedKey,
        HpkeStrategies? strategies)
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
        Strategies = strategies;
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

    public HpkeStrategies? Strategies { get; }

    public static HpkeConfig ForBaseSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[]? info = null)
        => new(HpkeModeKind.Base, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), null, null, null, null);

    public static HpkeConfig ForBaseRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[]? info = null)
        => new(HpkeModeKind.Base, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForPskSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.Psk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null, null);

    public static HpkeConfig ForPskRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.Psk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForAuthSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] senderPrivateKey,
        byte[]? info = null)
        => new(HpkeModeKind.Auth, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), null, null, null, null);

    public static HpkeConfig ForAuthRecipient(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPrivateKey,
        byte[] encappedKey,
        byte[] senderPublicKey,
        byte[]? info = null)
        => new(HpkeModeKind.Auth, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForAuthPskSender(
        HpkeKemAlgorithm kem,
        HpkeKdfAlgorithm kdf,
        HpkeAeadAlgorithm aead,
        byte[] recipientPublicKey,
        byte[] senderPrivateKey,
        byte[] psk,
        byte[] pskId,
        byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null, null);

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
        => new(HpkeModeKind.AuthPsk, DefaultSuiteIfSupported(kem, kdf, aead), kem, kdf, aead, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForBaseSender(HpkeSuite suite, byte[] recipientPublicKey, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), null, null, null, null);

    // Overload that accepts custom C# strategies for algorithms
    public static HpkeConfig ForBaseSender(HpkeSuite suite, byte[] recipientPublicKey, HpkeStrategies? strategies, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), null, null, null, strategies);

    public static HpkeConfig ForBaseRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)), null);

    // Overload that accepts custom C# strategies for algorithms
    public static HpkeConfig ForBaseRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, HpkeStrategies? strategies, byte[]? info = null)
        => new(HpkeModeKind.Base, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)), strategies);

    public static HpkeConfig ForPskSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.Psk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null, null);

    public static HpkeConfig ForPskRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.Psk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForAuthSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[]? info = null)
        => new(HpkeModeKind.Auth, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), null, null, null, null);

    public static HpkeConfig ForAuthRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[]? info = null)
        => new(HpkeModeKind.Auth, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), null, null, RequireBytes(encappedKey, nameof(encappedKey)), null);

    public static HpkeConfig ForAuthPskSender(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, RequireBytes(recipientPublicKey, nameof(recipientPublicKey)), null, RequireBytes(senderPrivateKey, nameof(senderPrivateKey)), null, Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), null, null);

    public static HpkeConfig ForAuthPskRecipient(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => new(HpkeModeKind.AuthPsk, suite, HpkeKemAlgorithm.DhKemP256HkdfSha256, HpkeKdfAlgorithm.HkdfSha256, HpkeAeadAlgorithm.Aes128Gcm, null, RequireBytes(recipientPrivateKey, nameof(recipientPrivateKey)), null, RequireBytes(senderPublicKey, nameof(senderPublicKey)), Normalize(info), RequireBytes(psk, nameof(psk)), Normalize(pskId), RequireBytes(encappedKey, nameof(encappedKey)), null);

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

        if (kem == HpkeKemAlgorithm.DhKemP256HkdfSha256 && kdf == HpkeKdfAlgorithm.HkdfSha256 && aead == HpkeAeadAlgorithm.Aes256Gcm)
        {
            return HpkeSuite.DhKemP256_HkdfSha256_AesGcm256;
        }

        if (kem == HpkeKemAlgorithm.DhKemX25519HkdfSha256 && kdf == HpkeKdfAlgorithm.HkdfSha256 && aead == HpkeAeadAlgorithm.Aes128Gcm)
        {
            return HpkeSuite.DhKemX25519_HkdfSha256_AesGcm128;
        }

        if (kem == HpkeKemAlgorithm.DhKemX25519HkdfSha256 && kdf == HpkeKdfAlgorithm.HkdfSha256 && aead == HpkeAeadAlgorithm.Aes256Gcm)
        {
            return HpkeSuite.DhKemX25519_HkdfSha256_AesGcm256;
        }

        if (kem == HpkeKemAlgorithm.DhKemP384HkdfSha384 && kdf == HpkeKdfAlgorithm.HkdfSha384 && aead == HpkeAeadAlgorithm.Aes128Gcm)
        {
            return HpkeSuite.DhKemP384_HkdfSha384_AesGcm128;
        }

        if (kem == HpkeKemAlgorithm.DhKemP384HkdfSha384 && kdf == HpkeKdfAlgorithm.HkdfSha384 && aead == HpkeAeadAlgorithm.Aes256Gcm)
        {
            return HpkeSuite.DhKemP384_HkdfSha384_AesGcm256;
        }

        if (kem == HpkeKemAlgorithm.DhKemP521HkdfSha512 && kdf == HpkeKdfAlgorithm.HkdfSha512 && aead == HpkeAeadAlgorithm.Aes128Gcm)
        {
            return HpkeSuite.DhKemP521_HkdfSha512_AesGcm128;
        }

        if (kem == HpkeKemAlgorithm.DhKemP521HkdfSha512 && kdf == HpkeKdfAlgorithm.HkdfSha512 && aead == HpkeAeadAlgorithm.Aes256Gcm)
        {
            return HpkeSuite.DhKemP521_HkdfSha512_AesGcm256;
        }

        throw new NotSupportedException($"Unsupported algorithm combination: {kem}/{kdf}/{aead}");
    }

    internal static Tuple<byte[], byte[]> GenerateDefaultKeyPair(HpkeKemAlgorithm kem) => kem switch
    {
        HpkeKemAlgorithm.DhKemP256HkdfSha256 => Crypto.generateEcdhP256KeyPair(),
        HpkeKemAlgorithm.DhKemX25519HkdfSha256 => Crypto.generateEcdhX25519KeyPair(),
        HpkeKemAlgorithm.DhKemP384HkdfSha384 => Crypto.generateEcdhP384KeyPair(),
        HpkeKemAlgorithm.DhKemP521HkdfSha512 => Crypto.generateEcdhP521KeyPair(),
        _ => throw new NotSupportedException($"Unsupported KEM: {kem}"),
    };

    internal static byte[] DeriveSharedSecret(HpkeKemAlgorithm kem, byte[] privateKey, byte[] peerPublicKey) => kem switch
    {
        HpkeKemAlgorithm.DhKemP256HkdfSha256 => Crypto.deriveSharedSecret(privateKey, peerPublicKey),
        HpkeKemAlgorithm.DhKemX25519HkdfSha256 => Crypto.deriveSharedSecretX25519(privateKey, peerPublicKey),
        HpkeKemAlgorithm.DhKemP384HkdfSha384 => Crypto.deriveSharedSecretP384(privateKey, peerPublicKey),
        HpkeKemAlgorithm.DhKemP521HkdfSha512 => Crypto.deriveSharedSecretP521(privateKey, peerPublicKey),
        _ => throw new NotSupportedException($"Unsupported KEM: {kem}"),
    };
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

    // Explicit named helpers to avoid overload ambiguity between PSK and Auth variants.
    public static HpkeSenderContext SetupPsk(HpkeSuite suite, byte[] recipientPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForPskSender(suite, recipientPublicKey, psk, pskId, info));

    public static HpkeSenderContext SetupAuth(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthSender(suite, recipientPublicKey, senderPrivateKey, info));

    public static HpkeSenderContext SetupAuthPsk(HpkeSuite suite, byte[] recipientPublicKey, byte[] senderPrivateKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthPskSender(suite, recipientPublicKey, senderPrivateKey, psk, pskId, info));

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

    // Explicit named helpers to avoid overload ambiguity between PSK and Auth variants.
    public static HpkeRecipientContext SetupPsk(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForPskRecipient(suite, recipientPrivateKey, encappedKey, psk, pskId, info));

    public static HpkeRecipientContext SetupAuth(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthRecipient(suite, recipientPrivateKey, encappedKey, senderPublicKey, info));

    public static HpkeRecipientContext SetupAuthPsk(HpkeSuite suite, byte[] recipientPrivateKey, byte[] encappedKey, byte[] senderPublicKey, byte[] psk, byte[] pskId, byte[]? info = null)
        => Setup(HpkeConfig.ForAuthPskRecipient(suite, recipientPrivateKey, encappedKey, senderPublicKey, psk, pskId, info));

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
        // If C# strategies are provided on the config, perform the operation in C# using them.
        if (config.Strategies is not null)
        {
            var s = config.Strategies;
            switch (config.Mode)
            {
                case HpkeModeKind.Base:
                {
                    // Encapsulate
                    byte[] epk;
                    byte[] shared1;
                    if (s.KemEncapsulate is not null)
                    {
                        (epk, shared1) = s.KemEncapsulate(config.RecipientPublicKey!);
                    }
                    else
                    {
                        var pair = HpkeConfig.GenerateDefaultKeyPair(config.Kem);
                        epk = pair.Item2;
                        shared1 = HpkeConfig.DeriveSharedSecret(config.Kem, pair.Item1, config.RecipientPublicKey!);
                    }

                    // KDF
                    byte[] prk;
                    if (s.KdfExtract is not null)
                        prk = s.KdfExtract(null, shared1);
                    else
                        prk = Crypto.hkdfExtract(null, shared1);

                    byte[] key;
                    if (s.KdfExpand is not null)
                        key = s.KdfExpand(prk, config.Info, s.KeySize);
                    else
                        key = Crypto.hkdfExpand(prk, config.Info, s.KeySize);

                    var nonceInfo = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonce;
                    if (s.KdfExpand is not null)
                        nonce = s.KdfExpand(prk, nonceInfo, s.NonceSize);
                    else
                        nonce = Crypto.hkdfExpand(prk, nonceInfo, s.NonceSize);

                    byte[] ct;
                    if (s.AeadEncrypt is not null)
                        ct = s.AeadEncrypt(key, nonce, aad, plaintext);
                    else
                        ct = Crypto.aesGcmEncrypt(key, nonce, aad, plaintext);
                    return new HpkeSealedValue(epk, ct);
                }
                case HpkeModeKind.Psk:
                {
                    byte[] epk;
                    byte[] shared1;
                    if (s.KemEncapsulate is not null)
                    {
                        (epk, shared1) = s.KemEncapsulate(config.RecipientPublicKey!);
                    }
                    else
                    {
                        var pair = HpkeConfig.GenerateDefaultKeyPair(config.Kem);
                        epk = pair.Item2;
                        shared1 = HpkeConfig.DeriveSharedSecret(config.Kem, pair.Item1, config.RecipientPublicKey!);
                    }

                    byte[] prkPsk;
                    if (s.KdfExtract is not null)
                        prkPsk = s.KdfExtract(config.Psk, shared1);
                    else
                        prkPsk = Crypto.hkdfExtract(config.Psk, shared1);

                    byte[] keyPsk;
                    if (s.KdfExpand is not null)
                        keyPsk = s.KdfExpand(prkPsk, config.Info, s.KeySize);
                    else
                        keyPsk = Crypto.hkdfExpand(prkPsk, config.Info, s.KeySize);

                    var nonceInfoPsk = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] noncePsk;
                    if (s.KdfExpand is not null)
                        noncePsk = s.KdfExpand(prkPsk, nonceInfoPsk, s.NonceSize);
                    else
                        noncePsk = Crypto.hkdfExpand(prkPsk, nonceInfoPsk, s.NonceSize);

                    byte[] ctPsk;
                    if (s.AeadEncrypt is not null)
                        ctPsk = s.AeadEncrypt(keyPsk, noncePsk, aad, plaintext);
                    else
                        ctPsk = Crypto.aesGcmEncrypt(keyPsk, noncePsk, aad, plaintext);
                    return new HpkeSealedValue(epk, ctPsk);
                }
                case HpkeModeKind.Auth:
                {
                    byte[] epk;
                    byte[] shared1;
                    if (s.KemEncapsulate is not null)
                    {
                        (epk, shared1) = s.KemEncapsulate(config.RecipientPublicKey!);
                    }
                    else
                    {
                        var pair = HpkeConfig.GenerateDefaultKeyPair(config.Kem);
                        epk = pair.Item2;
                        shared1 = HpkeConfig.DeriveSharedSecret(config.Kem, pair.Item1, config.RecipientPublicKey!);
                    }

                    var sharedAuth = HpkeConfig.DeriveSharedSecret(config.Kem, config.SenderPrivateKey!, config.RecipientPublicKey!);
                    var combined = ConcatArrays(shared1, sharedAuth);
                    byte[] prkAuth;
                    if (s.KdfExtract is not null)
                        prkAuth = s.KdfExtract(null, combined);
                    else
                        prkAuth = Crypto.hkdfExtract(null, combined);

                    byte[] keyAuth;
                    if (s.KdfExpand is not null)
                        keyAuth = s.KdfExpand(prkAuth, config.Info, s.KeySize);
                    else
                        keyAuth = Crypto.hkdfExpand(prkAuth, config.Info, s.KeySize);

                    var nonceInfoAuth = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonceAuth;
                    if (s.KdfExpand is not null)
                        nonceAuth = s.KdfExpand(prkAuth, nonceInfoAuth, s.NonceSize);
                    else
                        nonceAuth = Crypto.hkdfExpand(prkAuth, nonceInfoAuth, s.NonceSize);

                    byte[] ctAuth;
                    if (s.AeadEncrypt is not null)
                        ctAuth = s.AeadEncrypt(keyAuth, nonceAuth, aad, plaintext);
                    else
                        ctAuth = Crypto.aesGcmEncrypt(keyAuth, nonceAuth, aad, plaintext);
                    return new HpkeSealedValue(epk, ctAuth);
                }
                case HpkeModeKind.AuthPsk:
                {
                    byte[] epk;
                    byte[] shared1;
                    if (s.KemEncapsulate is not null)
                    {
                        (epk, shared1) = s.KemEncapsulate(config.RecipientPublicKey!);
                    }
                    else
                    {
                        var pair = HpkeConfig.GenerateDefaultKeyPair(config.Kem);
                        epk = pair.Item2;
                        shared1 = HpkeConfig.DeriveSharedSecret(config.Kem, pair.Item1, config.RecipientPublicKey!);
                    }

                    var sharedAuth = HpkeConfig.DeriveSharedSecret(config.Kem, config.SenderPrivateKey!, config.RecipientPublicKey!);
                    var combined = ConcatArrays(shared1, sharedAuth);
                    byte[] prkAuthPsk;
                    if (s.KdfExtract is not null)
                        prkAuthPsk = s.KdfExtract(config.Psk, combined);
                    else
                        prkAuthPsk = Crypto.hkdfExtract(config.Psk, combined);

                    byte[] keyAuthPsk;
                    if (s.KdfExpand is not null)
                        keyAuthPsk = s.KdfExpand(prkAuthPsk, config.Info, s.KeySize);
                    else
                        keyAuthPsk = Crypto.hkdfExpand(prkAuthPsk, config.Info, s.KeySize);

                    var nonceInfoAuthPsk = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonceAuthPsk;
                    if (s.KdfExpand is not null)
                        nonceAuthPsk = s.KdfExpand(prkAuthPsk, nonceInfoAuthPsk, s.NonceSize);
                    else
                        nonceAuthPsk = Crypto.hkdfExpand(prkAuthPsk, nonceInfoAuthPsk, s.NonceSize);

                    byte[] ctAuthPsk;
                    if (s.AeadEncrypt is not null)
                        ctAuthPsk = s.AeadEncrypt(keyAuthPsk, nonceAuthPsk, aad, plaintext);
                    else
                        ctAuthPsk = Crypto.aesGcmEncrypt(keyAuthPsk, nonceAuthPsk, aad, plaintext);
                    return new HpkeSealedValue(epk, ctAuthPsk);
                }
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

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
        if (config.Strategies is not null)
        {
            var s = config.Strategies;
            switch (config.Mode)
            {
                case HpkeModeKind.Base:
                {
                    byte[] shared1;
                    if (s.KemDecapsulate is not null)
                    {
                        shared1 = s.KemDecapsulate(config.RecipientPrivateKey!, config.EncappedKey!);
                    }
                    else
                    {
                        shared1 = HpkeConfig.DeriveSharedSecret(config.Kem, config.RecipientPrivateKey!, config.EncappedKey!);
                    }

                    byte[] prkOpen;
                    if (s.KdfExtract is not null)
                        prkOpen = s.KdfExtract(null, shared1);
                    else
                        prkOpen = Crypto.hkdfExtract(null, shared1);

                    byte[] keyOpen;
                    if (s.KdfExpand is not null)
                        keyOpen = s.KdfExpand(prkOpen, config.Info, s.KeySize);
                    else
                        keyOpen = Crypto.hkdfExpand(prkOpen, config.Info, 32);

                    var nonceInfoOpen = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonceOpen;
                    if (s.KdfExpand is not null)
                        nonceOpen = s.KdfExpand(prkOpen, nonceInfoOpen, s.NonceSize);
                    else
                        nonceOpen = Crypto.hkdfExpand(prkOpen, nonceInfoOpen, 12);

                    byte[]? ptOpen;
                    if (s.AeadDecrypt is not null)
                        ptOpen = s.AeadDecrypt(keyOpen, nonceOpen, aad, ciphertext);
                    else
                    {
                        var maybe = Crypto.aesGcmDecrypt(keyOpen, nonceOpen, aad, ciphertext);
                        ptOpen = maybe == null ? null : maybe.Value;
                    }

                    if (ptOpen is null) throw new CryptographicException("Open failed: decryption failed");
                    return ptOpen;
                }
                case HpkeModeKind.Psk:
                {
                    byte[] shared1 = s.KemDecapsulate is not null ? s.KemDecapsulate(config.RecipientPrivateKey!, config.EncappedKey!) : HpkeConfig.DeriveSharedSecret(config.Kem, config.RecipientPrivateKey!, config.EncappedKey!);

                    byte[] prkPskOpen;
                    if (s.KdfExtract is not null)
                        prkPskOpen = s.KdfExtract(config.Psk, shared1);
                    else
                        prkPskOpen = Crypto.hkdfExtract(config.Psk, shared1);

                    byte[] keyPskOpen;
                    if (s.KdfExpand is not null)
                        keyPskOpen = s.KdfExpand(prkPskOpen, config.Info, s.KeySize);
                    else
                        keyPskOpen = Crypto.hkdfExpand(prkPskOpen, config.Info, 32);

                    var nonceInfoPskOpen = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] noncePskOpen;
                    if (s.KdfExpand is not null)
                        noncePskOpen = s.KdfExpand(prkPskOpen, nonceInfoPskOpen, s.NonceSize);
                    else
                        noncePskOpen = Crypto.hkdfExpand(prkPskOpen, nonceInfoPskOpen, 12);

                    byte[]? ptPskOpen;
                    if (s.AeadDecrypt is not null)
                        ptPskOpen = s.AeadDecrypt(keyPskOpen, noncePskOpen, aad, ciphertext);
                    else
                    {
                        var maybe = Crypto.aesGcmDecrypt(keyPskOpen, noncePskOpen, aad, ciphertext);
                        ptPskOpen = maybe == null ? null : maybe.Value;
                    }

                    if (ptPskOpen is null) throw new CryptographicException("Open failed: decryption failed");
                    return ptPskOpen;
                }
                case HpkeModeKind.Auth:
                {
                    byte[] shared1 = s.KemDecapsulate is not null ? s.KemDecapsulate(config.RecipientPrivateKey!, config.EncappedKey!) : HpkeConfig.DeriveSharedSecret(config.Kem, config.RecipientPrivateKey!, config.EncappedKey!);
                    var sharedAuth = HpkeConfig.DeriveSharedSecret(config.Kem, config.SenderPublicKey!, config.RecipientPrivateKey!);
                    var combined = ConcatArrays(shared1, sharedAuth);

                    byte[] prkAuthOpen;
                    if (s.KdfExtract is not null)
                        prkAuthOpen = s.KdfExtract(null, combined);
                    else
                        prkAuthOpen = Crypto.hkdfExtract(null, combined);

                    byte[] keyAuthOpen;
                    if (s.KdfExpand is not null)
                        keyAuthOpen = s.KdfExpand(prkAuthOpen, config.Info, s.KeySize);
                    else
                        keyAuthOpen = Crypto.hkdfExpand(prkAuthOpen, config.Info, 32);

                    var nonceInfoAuthOpen = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonceAuthOpen;
                    if (s.KdfExpand is not null)
                        nonceAuthOpen = s.KdfExpand(prkAuthOpen, nonceInfoAuthOpen, s.NonceSize);
                    else
                        nonceAuthOpen = Crypto.hkdfExpand(prkAuthOpen, nonceInfoAuthOpen, 12);

                    byte[]? ptAuthOpen;
                    if (s.AeadDecrypt is not null)
                        ptAuthOpen = s.AeadDecrypt(keyAuthOpen, nonceAuthOpen, aad, ciphertext);
                    else
                    {
                        var maybe = Crypto.aesGcmDecrypt(keyAuthOpen, nonceAuthOpen, aad, ciphertext);
                        ptAuthOpen = maybe == null ? null : maybe.Value;
                    }

                    if (ptAuthOpen is null) throw new CryptographicException("Open failed: decryption failed");
                    return ptAuthOpen;
                }
                case HpkeModeKind.AuthPsk:
                {
                    byte[] shared1 = s.KemDecapsulate is not null ? s.KemDecapsulate(config.RecipientPrivateKey!, config.EncappedKey!) : HpkeConfig.DeriveSharedSecret(config.Kem, config.RecipientPrivateKey!, config.EncappedKey!);
                    var sharedAuth = HpkeConfig.DeriveSharedSecret(config.Kem, config.SenderPublicKey!, config.RecipientPrivateKey!);
                    var combined = ConcatArrays(shared1, sharedAuth);

                    byte[] prkAuthPskOpen;
                    if (s.KdfExtract is not null)
                        prkAuthPskOpen = s.KdfExtract(config.Psk, combined);
                    else
                        prkAuthPskOpen = Crypto.hkdfExtract(config.Psk, combined);

                    byte[] keyAuthPskOpen;
                    if (s.KdfExpand is not null)
                        keyAuthPskOpen = s.KdfExpand(prkAuthPskOpen, config.Info, s.KeySize);
                    else
                        keyAuthPskOpen = Crypto.hkdfExpand(prkAuthPskOpen, config.Info, 32);

                    var nonceInfoAuthPskOpen = ConcatArrays(config.Info, new byte[] { 0 });

                    byte[] nonceAuthPskOpen;
                    if (s.KdfExpand is not null)
                        nonceAuthPskOpen = s.KdfExpand(prkAuthPskOpen, nonceInfoAuthPskOpen, s.NonceSize);
                    else
                        nonceAuthPskOpen = Crypto.hkdfExpand(prkAuthPskOpen, nonceInfoAuthPskOpen, 12);

                    byte[]? ptAuthPskOpen;
                    if (s.AeadDecrypt is not null)
                        ptAuthPskOpen = s.AeadDecrypt(keyAuthPskOpen, nonceAuthPskOpen, aad, ciphertext);
                    else
                    {
                        var maybe = Crypto.aesGcmDecrypt(keyAuthPskOpen, nonceAuthPskOpen, aad, ciphertext);
                        ptAuthPskOpen = maybe == null ? null : maybe.Value;
                    }

                    if (ptAuthPskOpen is null) throw new CryptographicException("Open failed: decryption failed");
                    return ptAuthPskOpen;
                }
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

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
        HpkeSuite.DhKemP256_HkdfSha256_AesGcm256 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP256HkdfSha256,
            global::Hpke.Core.KdfAlgorithm.HkdfSha256,
            global::Hpke.Core.AeadAlgorithm.Aes256Gcm),
        HpkeSuite.DhKemX25519_HkdfSha256_AesGcm128 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemX25519HkdfSha256,
            global::Hpke.Core.KdfAlgorithm.HkdfSha256,
            global::Hpke.Core.AeadAlgorithm.Aes128Gcm),
        HpkeSuite.DhKemX25519_HkdfSha256_AesGcm256 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemX25519HkdfSha256,
            global::Hpke.Core.KdfAlgorithm.HkdfSha256,
            global::Hpke.Core.AeadAlgorithm.Aes256Gcm),
        HpkeSuite.DhKemP384_HkdfSha384_AesGcm128 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP384HkdfSha384,
            global::Hpke.Core.KdfAlgorithm.HkdfSha384,
            global::Hpke.Core.AeadAlgorithm.Aes128Gcm),
        HpkeSuite.DhKemP384_HkdfSha384_AesGcm256 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP384HkdfSha384,
            global::Hpke.Core.KdfAlgorithm.HkdfSha384,
            global::Hpke.Core.AeadAlgorithm.Aes256Gcm),
        HpkeSuite.DhKemP521_HkdfSha512_AesGcm128 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP521HkdfSha512,
            global::Hpke.Core.KdfAlgorithm.HkdfSha512,
            global::Hpke.Core.AeadAlgorithm.Aes128Gcm),
        HpkeSuite.DhKemP521_HkdfSha512_AesGcm256 => new global::Hpke.Core.HpkeSuite(
            global::Hpke.Core.KemAlgorithm.DhKemP521HkdfSha512,
            global::Hpke.Core.KdfAlgorithm.HkdfSha512,
            global::Hpke.Core.AeadAlgorithm.Aes256Gcm),
        _ => throw new NotSupportedException($"Unsupported suite: {suite}"),
    };

    private static byte[] Require(byte[]? value, string name)
        => value ?? throw new ArgumentNullException(name);

    private static byte[] ConcatArrays(byte[] a, byte[] b)
    {
        var res = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, res, 0, a.Length);
        Buffer.BlockCopy(b, 0, res, a.Length, b.Length);
        return res;
    }
}
