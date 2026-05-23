namespace Hpke.Core

open System.Security.Cryptography

type HpkeMode =
    | Base
    | Psk
    | Auth
    | AuthPsk

type KemAlgorithm =
    | DhKemP256HkdfSha256
    | DhKemP384HkdfSha384
    | DhKemP521HkdfSha512
    | CustomKem of string

type KdfAlgorithm =
    | HkdfSha256
    | HkdfSha384
    | HkdfSha512
    | CustomKdf of string

type AeadAlgorithm =
    | Aes128Gcm
    | Aes256Gcm
    | ChaCha20Poly1305
    | CustomAead of string

type HpkeSuite = {
    Kem: KemAlgorithm
    Kdf: KdfAlgorithm
    Aead: AeadAlgorithm
}

// Strategy records to allow plugging custom algorithm implementations at runtime.
type KemStrategy = {
    Encapsulate: byte[] -> byte[] * byte[]
    Decapsulate: byte[] -> byte[] -> byte[]
}

type KdfStrategy = {
    Extract: byte[] option -> byte[] -> byte[]
    Expand: byte[] -> byte[] -> int -> byte[]
}

type AeadStrategy = {
    Encrypt: byte[] -> byte[] -> byte[] -> byte[] -> byte[]
    Decrypt: byte[] -> byte[] -> byte[] -> byte[] -> byte[] option
    KeySize: int
    NonceSize: int
    TagSize: int
}

type HpkeStrategies = {
    KemStr: KemStrategy option
    KdfStr: KdfStrategy option
    AeadStr: AeadStrategy option
}

module Suites =
    let DefaultAes128 : HpkeSuite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let DefaultAes256 : HpkeSuite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes256Gcm
    }

    let DefaultP384Aes128 : HpkeSuite = {
        Kem = DhKemP384HkdfSha384
        Kdf = HkdfSha384
        Aead = Aes128Gcm
    }

    let DefaultP384Aes256 : HpkeSuite = {
        Kem = DhKemP384HkdfSha384
        Kdf = HkdfSha384
        Aead = Aes256Gcm
    }

    let DefaultP521Aes128 : HpkeSuite = {
        Kem = DhKemP521HkdfSha512
        Kdf = HkdfSha512
        Aead = Aes128Gcm
    }

    let DefaultP521Aes256 : HpkeSuite = {
        Kem = DhKemP521HkdfSha512
        Kdf = HkdfSha512
        Aead = Aes256Gcm
    }

    let Default = DefaultAes128

    let create kem kdf aead : HpkeSuite = {
        Kem = kem
        Kdf = kdf
        Aead = aead
    }

    let Supported = [ DefaultAes128; DefaultAes256; DefaultP384Aes128; DefaultP384Aes256; DefaultP521Aes128; DefaultP521Aes256 ]

    let isSupportedKem = function
        | DhKemP256HkdfSha256
        | DhKemP384HkdfSha384
        | DhKemP521HkdfSha512 -> true
        | _ -> false

    let isSupportedKdf = function
        | CustomKdf _ -> false
        | _ -> true

    let isSupportedAead = function
        | Aes128Gcm
        | Aes256Gcm -> true
        | _ -> false

    let isSupportedSuite (suite: HpkeSuite) =
        isSupportedKem suite.Kem
        && isSupportedKdf suite.Kdf
        && isSupportedAead suite.Aead

    let kdfHash = function
        | HkdfSha256 -> HashAlgorithmName("SHA256")
        | HkdfSha384 -> HashAlgorithmName("SHA384")
        | HkdfSha512 -> HashAlgorithmName("SHA512")
        | CustomKdf name -> invalidArg "kdf" (sprintf "Unsupported custom KDF %s; provide a custom strategy instead" name)

    let aeadKeySize = function
        | Aes128Gcm -> 16
        | Aes256Gcm -> 32
        | ChaCha20Poly1305 -> 32
        | CustomAead name -> invalidArg "aead" (sprintf "Unsupported custom AEAD %s; provide a custom strategy instead" name)


type BaseSealRequest = {
    Suite: HpkeSuite
    RecipientPublicKey: byte[]
    Info: byte[]
    Aad: byte[]
    Plaintext: byte[]
}

type BaseSealResult = {
    EncappedKey: byte[]
    Ciphertext: byte[]
}

type BaseOpenRequest = {
    Suite: HpkeSuite
    RecipientPrivateKey: byte[]
    EncappedKey: byte[]
    Info: byte[]
    Aad: byte[]
    Ciphertext: byte[]
}

type PskSealRequest = {
    Suite: HpkeSuite
    RecipientPublicKey: byte[]
    Psk: byte[]
    PskId: byte[]
    Info: byte[]
    Aad: byte[]
    Plaintext: byte[]
}

type PskOpenRequest = {
    Suite: HpkeSuite
    RecipientPrivateKey: byte[]
    EncappedKey: byte[]
    Psk: byte[]
    PskId: byte[]
    Info: byte[]
    Aad: byte[]
    Ciphertext: byte[]
}

type AuthSealRequest = {
    Suite: HpkeSuite
    RecipientPublicKey: byte[]
    SenderPrivateKey: byte[]
    Info: byte[]
    Aad: byte[]
    Plaintext: byte[]
}

type AuthOpenRequest = {
    Suite: HpkeSuite
    RecipientPrivateKey: byte[]
    SenderPublicKey: byte[]
    EncappedKey: byte[]
    Info: byte[]
    Aad: byte[]
    Ciphertext: byte[]
}

type AuthPskSealRequest = {
    Suite: HpkeSuite
    RecipientPublicKey: byte[]
    SenderPrivateKey: byte[]
    Psk: byte[]
    PskId: byte[]
    Info: byte[]
    Aad: byte[]
    Plaintext: byte[]
}

type AuthPskOpenRequest = {
    Suite: HpkeSuite
    RecipientPrivateKey: byte[]
    SenderPublicKey: byte[]
    EncappedKey: byte[]
    Psk: byte[]
    PskId: byte[]
    Info: byte[]
    Aad: byte[]
    Ciphertext: byte[]
}