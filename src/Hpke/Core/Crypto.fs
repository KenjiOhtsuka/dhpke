namespace Hpke.Core

open System
open System.Security.Cryptography

module Crypto =

    let generateEcdhP256KeyPair () : byte[] * byte[] =
        use e = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256)
        let priv = e.ExportPkcs8PrivateKey()
        let pub = e.PublicKey.ExportSubjectPublicKeyInfo()
        (priv, pub)

    let deriveSharedSecret (privatePkcs8: byte[]) (peerPublicSpki: byte[]) : byte[] =
        use priv = ECDiffieHellman.Create()
        let mutable read = 0
        priv.ImportPkcs8PrivateKey(ReadOnlySpan privatePkcs8, &read)
        use peer = ECDiffieHellman.Create()
        let mutable read2 = 0
        peer.ImportSubjectPublicKeyInfo(ReadOnlySpan peerPublicSpki, &read2)
        let secret = priv.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256)
        secret

    let hkdfExtract (salt: byte[]) (ikm: byte[]) : byte[] =
        let actualSalt = if isNull salt then Array.zeroCreate 32 else salt
        use hmac = new HMACSHA256(actualSalt)
        hmac.ComputeHash(ikm)

    let hkdfExpand (prk: byte[]) (info: byte[]) (length: int) : byte[] =
        let hashLen = 32
        let n = (length + hashLen - 1) / hashLen
        let mutable t = Array.empty<byte>
        let okm = Array.zeroCreate<byte> (n * hashLen)
        use hmac = new HMACSHA256(prk)
        for i in 1..n do
            let data = Array.concat [t; info; [| byte i |]]
            t <- hmac.ComputeHash(data)
            Array.Copy(t, 0, okm, (i-1)*hashLen, hashLen)
        okm.[0..length-1]

    let aesGcmEncrypt (key: byte[]) (nonce: byte[]) (aad: byte[]) (pt: byte[]) : byte[] =
        use aes = new AesGcm(key, 16)
        let ct = Array.zeroCreate<byte> pt.Length
        let tag = Array.zeroCreate<byte> 16
        aes.Encrypt(nonce, pt, ct, tag, aad)
        Array.concat [ct; tag]

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
