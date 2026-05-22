namespace Hpke.Core

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
    let Default : HpkeSuite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let create kem kdf aead : HpkeSuite = {
        Kem = kem
        Kdf = kdf
        Aead = aead
    }

    let Supported = [ Default ]

    let isSupportedKem = function
        | CustomKem _ -> false
        | _ -> true

    let isSupportedKdf = function
        | CustomKdf _ -> false
        | _ -> true

    let isSupportedAead = function
        | CustomAead _ -> false
        | _ -> true

    let isSupportedSuite (suite: HpkeSuite) =
        suite.Kem = Default.Kem
        && suite.Kdf = Default.Kdf
        && suite.Aead = Default.Aead


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