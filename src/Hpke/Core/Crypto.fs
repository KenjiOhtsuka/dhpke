namespace Hpke.Core

open System
open System.Security.Cryptography
open Org.BouncyCastle.Crypto.Agreement
open Org.BouncyCastle.Crypto.Generators
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.Pkcs
open Org.BouncyCastle.Security
open Org.BouncyCastle.X509

module Crypto =

    let private createP256Ecdh () =
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)

    let private createP384Ecdh () =
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384)

    let private createP521Ecdh () =
        ECDiffieHellman.Create(ECCurve.NamedCurves.nistP521)

    let private generateX25519KeyPair () : byte[] * byte[] =
        let gen = X25519KeyPairGenerator()
        gen.Init(X25519KeyGenerationParameters(SecureRandom()))
        let pair = gen.GenerateKeyPair()
        let privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded()
        let publicKey = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetEncoded()
        (privateKey, publicKey)

    let private publicKeyFromX25519PrivatePkcs8 (privatePkcs8: byte[]) : byte[] =
        let privateKey = PrivateKeyFactory.CreateKey(privatePkcs8) :?> X25519PrivateKeyParameters
        let publicKey = privateKey.GeneratePublicKey()
        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetEncoded()

    let private deriveX25519SharedSecret (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        let privateKey = PrivateKeyFactory.CreateKey(privatePkcs8) :?> X25519PrivateKeyParameters
        let peerPublicKey = PublicKeyFactory.CreateKey(peerPublicSpki) :?> X25519PublicKeyParameters
        let agreement = X25519Agreement()
        agreement.Init(privateKey)
        let raw = Array.zeroCreate<byte> agreement.AgreementSize
        agreement.CalculateAgreement(peerPublicKey, raw, 0)
        SHA256.HashData(raw)

    let private encapsulateWithX25519EphemeralPrivate (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        let epk = publicKeyFromX25519PrivatePkcs8 eskPkcs8
        let shared = deriveX25519SharedSecret eskPkcs8 recipientPublicSpki
        (epk, shared)

    let private getKemParameters = function
        | DhKemP256HkdfSha256 -> createP256Ecdh, HashAlgorithmName("SHA256")
        | DhKemP384HkdfSha384 -> createP384Ecdh, HashAlgorithmName("SHA384")
        | DhKemP521HkdfSha512 -> createP521Ecdh, HashAlgorithmName("SHA512")
        | DhKemX25519HkdfSha256 -> invalidArg "kem" "X25519 uses dedicated key handling path"
        | CustomKem name -> invalidArg "kem" (sprintf "Unsupported KEM %s; provide a custom strategy instead" name)

    let private generateKeyPairUsing (createEcdh: unit -> ECDiffieHellman) : byte[] * byte[] =
        use e = createEcdh()
        let priv = e.ExportPkcs8PrivateKey()
        let pub = e.PublicKey.ExportSubjectPublicKeyInfo()
        (priv, pub)

    let private publicKeyFromPrivatePkcs8Using (createEcdh: unit -> ECDiffieHellman) (privatePkcs8: byte[]) : byte[] =
        use priv = createEcdh()
        let mutable read = 0
        priv.ImportPkcs8PrivateKey(ReadOnlySpan privatePkcs8, &read)
        priv.PublicKey.ExportSubjectPublicKeyInfo()

    let private deriveSharedSecretUsing (createEcdh: unit -> ECDiffieHellman) (hashAlgorithm: HashAlgorithmName) (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        use priv = createEcdh()
        let mutable read = 0
        priv.ImportPkcs8PrivateKey(ReadOnlySpan privatePkcs8, &read)
        use peer = createEcdh()
        let mutable read2 = 0
        peer.ImportSubjectPublicKeyInfo(ReadOnlySpan peerPublicSpki, &read2)
        priv.DeriveKeyFromHash(peer.PublicKey, hashAlgorithm)

    let private encapsulateWithEphemeralPrivateUsing (createEcdh: unit -> ECDiffieHellman) (hashAlgorithm: HashAlgorithmName) (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        let epk = publicKeyFromPrivatePkcs8Using createEcdh eskPkcs8
        let shared = deriveSharedSecretUsing createEcdh hashAlgorithm eskPkcs8 recipientPublicSpki
        (epk, shared)

    let generateKeyPairForKem kem =
        match kem with
        | DhKemX25519HkdfSha256 -> generateX25519KeyPair ()
        | _ ->
            let createEcdh, _ = getKemParameters kem
            generateKeyPairUsing createEcdh

    let publicKeyFromPrivatePkcs8ForKem kem privatePkcs8 =
        match kem with
        | DhKemX25519HkdfSha256 -> publicKeyFromX25519PrivatePkcs8 privatePkcs8
        | _ ->
            let createEcdh, _ = getKemParameters kem
            publicKeyFromPrivatePkcs8Using createEcdh privatePkcs8

    let deriveSharedSecretForKem kem privatePkcs8 peerPublicSpki =
        match kem with
        | DhKemX25519HkdfSha256 -> deriveX25519SharedSecret privatePkcs8 peerPublicSpki
        | _ ->
            let createEcdh, hashAlgorithm = getKemParameters kem
            deriveSharedSecretUsing createEcdh hashAlgorithm privatePkcs8 peerPublicSpki

    let encapsulateWithEphemeralPrivateForKem kem eskPkcs8 recipientPublicSpki =
        match kem with
        | DhKemX25519HkdfSha256 -> encapsulateWithX25519EphemeralPrivate eskPkcs8 recipientPublicSpki
        | _ ->
            let createEcdh, hashAlgorithm = getKemParameters kem
            encapsulateWithEphemeralPrivateUsing createEcdh hashAlgorithm eskPkcs8 recipientPublicSpki

    let generateEcdhP256KeyPair () : byte[] * byte[] =
        generateKeyPairUsing createP256Ecdh

    let generateEcdhP384KeyPair () : byte[] * byte[] =
        generateKeyPairUsing createP384Ecdh

    let generateEcdhP521KeyPair () : byte[] * byte[] =
        generateKeyPairUsing createP521Ecdh

    let generateEcdhX25519KeyPair () : byte[] * byte[] =
        generateX25519KeyPair ()

    let publicKeyFromPrivatePkcs8 (privatePkcs8: byte[]) : byte[] =
        publicKeyFromPrivatePkcs8Using createP256Ecdh privatePkcs8

    let publicKeyFromPrivatePkcs8P384 (privatePkcs8: byte[]) : byte[] =
        publicKeyFromPrivatePkcs8Using createP384Ecdh privatePkcs8

    let publicKeyFromPrivatePkcs8P521 (privatePkcs8: byte[]) : byte[] =
        publicKeyFromPrivatePkcs8Using createP521Ecdh privatePkcs8

    let publicKeyFromPrivatePkcs8X25519 (privatePkcs8: byte[]) : byte[] =
        publicKeyFromX25519PrivatePkcs8 privatePkcs8

    let deriveSharedSecret (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        deriveSharedSecretUsing createP256Ecdh HashAlgorithmName.SHA256 privatePkcs8 peerPublicSpki

    let deriveSharedSecretP384 (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        deriveSharedSecretUsing createP384Ecdh HashAlgorithmName.SHA384 privatePkcs8 peerPublicSpki

    let deriveSharedSecretP521 (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        deriveSharedSecretUsing createP521Ecdh HashAlgorithmName.SHA512 privatePkcs8 peerPublicSpki

    let deriveSharedSecretX25519 (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        deriveX25519SharedSecret privatePkcs8 peerPublicSpki

    /// Encapsulate using a provided ephemeral private key (PKCS#8) and recipient public SPKI.
    /// Returns (epk_spki, shared_secret)
    let encapsulateWithEphemeralPrivate (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        encapsulateWithEphemeralPrivateUsing createP256Ecdh HashAlgorithmName.SHA256 eskPkcs8 recipientPublicSpki

    let encapsulateWithEphemeralPrivateP384 (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        encapsulateWithEphemeralPrivateUsing createP384Ecdh HashAlgorithmName.SHA384 eskPkcs8 recipientPublicSpki

    let encapsulateWithEphemeralPrivateP521 (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        encapsulateWithEphemeralPrivateUsing createP521Ecdh HashAlgorithmName.SHA512 eskPkcs8 recipientPublicSpki

    let encapsulateWithEphemeralPrivateX25519 (eskPkcs8: byte[]) (recipientPublicSpki: byte[]) : byte[] * byte[] =
        encapsulateWithX25519EphemeralPrivate eskPkcs8 recipientPublicSpki

    let private hashLength = function
        | h when h = HashAlgorithmName("SHA256") -> 32
        | h when h = HashAlgorithmName("SHA384") -> 48
        | h when h = HashAlgorithmName("SHA512") -> 64
        | h -> invalidArg "hashAlgorithm" (sprintf "Unsupported hash algorithm %A" h)

    let private createHmac = function
        | h when h = HashAlgorithmName("SHA256") -> fun (key: byte[]) -> new HMACSHA256(key) :> HMAC
        | h when h = HashAlgorithmName("SHA384") -> fun (key: byte[]) -> new HMACSHA384(key) :> HMAC
        | h when h = HashAlgorithmName("SHA512") -> fun (key: byte[]) -> new HMACSHA512(key) :> HMAC
        | h -> invalidArg "hashAlgorithm" (sprintf "Unsupported hash algorithm %A" h)

    let hkdfExtractWithHash hashAlgorithm (salt: byte[]) (ikm: byte[]) : byte[] =
        let actualSalt = if isNull salt then Array.zeroCreate (hashLength hashAlgorithm) else salt
        use hmac = createHmac hashAlgorithm actualSalt
        hmac.ComputeHash(ikm)

    let hkdfExpandWithHash hashAlgorithm (prk: byte[]) (info: byte[]) (length: int) : byte[] =
        let hashLen = hashLength hashAlgorithm
        let n = (length + hashLen - 1) / hashLen
        let mutable t = Array.empty<byte>
        let okm = Array.zeroCreate<byte> (n * hashLen)
        use hmac = createHmac hashAlgorithm prk
        for i in 1..n do
            let data = Array.concat [ t; info; [| byte i |] ]
            t <- hmac.ComputeHash(data)
            Array.Copy(t, 0, okm, (i - 1) * hashLen, hashLen)
        okm.[0..length-1]

    let hkdfExtract (salt: byte[]) (ikm: byte[]) : byte[] =
        hkdfExtractWithHash (HashAlgorithmName("SHA256")) salt ikm

    let hkdfExpand (prk: byte[]) (info: byte[]) (length: int) : byte[] =
        hkdfExpandWithHash (HashAlgorithmName("SHA256")) prk info length

    let aesGcmEncrypt (key: byte[]) (nonce: byte[]) (aad: byte[]) (pt: byte[]) : byte[] =
        use aes = new AesGcm(key, 16)
        let ct = Array.zeroCreate<byte> pt.Length
        let tag = Array.zeroCreate<byte> 16
        aes.Encrypt(nonce, pt, ct, tag, aad)
        Array.concat [ ct; tag ]

    let aesGcmDecrypt (key: byte[]) (nonce: byte[]) (aad: byte[]) (ctAndTag: byte[]) : byte[] option =
        if ctAndTag.Length < 16 then None else
        let tag = ctAndTag.[ctAndTag.Length-16..]
        let ct = ctAndTag.[0..ctAndTag.Length-17]
        try
            use aes = new AesGcm(key, 16)
            let pt = Array.zeroCreate<byte> ct.Length
            aes.Decrypt(nonce, ct, tag, pt, aad)
            Some pt
        with
        | _ -> None
