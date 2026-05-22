namespace Hpke

open Hpke.Core

module Hpke =
    let BaseSeal = Base.Seal
    let BaseOpen = Base.Open
    let PskSeal = Psk.Seal
    let PskOpen = Psk.Open
    let AuthSeal = Auth.Seal
    let AuthOpen = Auth.Open
    let AuthPskSeal = AuthPsk.Seal
    let AuthPskOpen = AuthPsk.Open

    let BaseSealWithAlgorithms kem kdf aead (request: BaseSealRequest) =
        Base.Seal { request with Suite = Suites.create kem kdf aead }

    let BaseOpenWithAlgorithms kem kdf aead (request: BaseOpenRequest) =
        Base.Open { request with Suite = Suites.create kem kdf aead }

    let PskSealWithAlgorithms kem kdf aead (request: PskSealRequest) =
        Psk.Seal { request with Suite = Suites.create kem kdf aead }

    let PskOpenWithAlgorithms kem kdf aead (request: PskOpenRequest) =
        Psk.Open { request with Suite = Suites.create kem kdf aead }

    let AuthSealWithAlgorithms kem kdf aead (request: AuthSealRequest) =
        Auth.Seal { request with Suite = Suites.create kem kdf aead }

    let AuthOpenWithAlgorithms kem kdf aead (request: AuthOpenRequest) =
        Auth.Open { request with Suite = Suites.create kem kdf aead }

    let AuthPskSealWithAlgorithms kem kdf aead (request: AuthPskSealRequest) =
        AuthPsk.Seal { request with Suite = Suites.create kem kdf aead }

    let AuthPskOpenWithAlgorithms kem kdf aead (request: AuthPskOpenRequest) =
        AuthPsk.Open { request with Suite = Suites.create kem kdf aead }

    // Helper that uses provided custom algorithm strategies when present; otherwise falls back to built-in Crypto.
    let private getKemEncap (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.KemStr.IsSome -> c.KemStr.Value.Encapsulate
        | _ -> fun recipientPub ->
            let (esk, epk) = Crypto.generateEcdhP256KeyPair()
            // derive shared secret using ephemeral private key and recipient public
            let shared = Crypto.deriveSharedSecret esk recipientPub
            (epk, shared)

    let private getKemDecap (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.KemStr.IsSome -> c.KemStr.Value.Decapsulate
        | _ -> fun recipientPriv enc -> Crypto.deriveSharedSecret recipientPriv enc

    let private getKdfExtract (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.KdfStr.IsSome -> c.KdfStr.Value.Extract
        | _ -> fun salt ikm -> Crypto.hkdfExtract (if salt.IsSome then salt.Value else null) ikm

    let private getKdfExpand (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.KdfStr.IsSome -> c.KdfStr.Value.Expand
        | _ -> fun prk info len -> Crypto.hkdfExpand prk info len

    let private getAeadEncrypt (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.AeadStr.IsSome -> c.AeadStr.Value.Encrypt
        | _ -> fun key nonce aad pt -> Crypto.aesGcmEncrypt key nonce aad pt

    let private getAeadDecrypt (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.AeadStr.IsSome -> c.AeadStr.Value.Decrypt
        | _ -> fun key nonce aad ct -> Crypto.aesGcmDecrypt key nonce aad ct

    // Key/nonce sizes pulled from strategy when present, otherwise default to AES-128-GCM sizes.
    let private getAeadKeySize (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.AeadStr.IsSome -> c.AeadStr.Value.KeySize
        | _ -> 16

    let private getAeadNonceSize (custom: HpkeStrategies option) =
        match custom with
        | Some c when c.AeadStr.IsSome -> c.AeadStr.Value.NonceSize
        | _ -> 12

    // Strategy-aware Base Seal/Open
    let BaseSealWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: BaseSealRequest) : Result<BaseSealResult, Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let encap = getKemEncap custom
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadEnc = getAeadEncrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let (epk, shared1) = encap request.RecipientPublicKey
                let prk = kdfExtract None shared1
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                let ct = aeadEnc key nonce request.Aad request.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with _ -> Error (Hpke.Core.NotImplemented "HPKE Base seal with strategies")

    let BaseOpenWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: BaseOpenRequest) : Result<byte[], Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadDec = getAeadDecrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let shared1 = decap request.RecipientPrivateKey request.EncappedKey
                let prk = kdfExtract None shared1
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                match aeadDec key nonce request.Aad request.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (Hpke.Core.InvalidArgument("Ciphertext", "decryption failed"))
            with _ -> Error (Hpke.Core.NotImplemented "HPKE Base open with strategies")

    // Strategy-aware PSK
    let PskSealWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: PskSealRequest) : Result<BaseSealResult, Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let encap = getKemEncap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadEnc = getAeadEncrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let (epk, shared1) = encap request.RecipientPublicKey
                let prk = kdfExtract (Some request.Psk) shared1
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                let ct = aeadEnc key nonce request.Aad request.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with _ -> Error (Hpke.Core.NotImplemented "HPKE PSK seal with strategies")

    let PskOpenWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: PskOpenRequest) : Result<byte[], Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadDec = getAeadDecrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let shared1 = decap request.RecipientPrivateKey request.EncappedKey
                let prk = kdfExtract (Some request.Psk) shared1
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                match aeadDec key nonce request.Aad request.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (Hpke.Core.InvalidArgument("Ciphertext", "decryption failed"))
            with _ -> Error (Hpke.Core.NotImplemented "HPKE PSK open with strategies")

    // Strategy-aware Auth
    let AuthSealWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: AuthSealRequest) : Result<BaseSealResult, Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let encap = getKemEncap custom
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadEnc = getAeadEncrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                // encapsulate using sender ephemeral but include sender static contribution via SenderPrivateKey
                let (epk, shared1) = encap request.RecipientPublicKey
                // incorporate sender auth using ECDH between sender private and recipient public
                let sharedAuth = Crypto.deriveSharedSecret request.SenderPrivateKey request.RecipientPublicKey
                // combine secrets by concatenation (simple composition for this implementation)
                let combined = Array.concat [ shared1; sharedAuth ]
                let prk = kdfExtract None combined
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                let ct = aeadEnc key nonce request.Aad request.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with _ -> Error (Hpke.Core.NotImplemented "HPKE Auth seal with strategies")

    let AuthOpenWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: AuthOpenRequest) : Result<byte[], Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadDec = getAeadDecrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let shared1 = decap request.RecipientPrivateKey request.EncappedKey
                let sharedAuth = Crypto.deriveSharedSecret request.SenderPublicKey request.RecipientPrivateKey
                let combined = Array.concat [ shared1; sharedAuth ]
                let prk = kdfExtract None combined
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                match aeadDec key nonce request.Aad request.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (Hpke.Core.InvalidArgument("Ciphertext", "decryption failed"))
            with _ -> Error (Hpke.Core.NotImplemented "HPKE Auth open with strategies")

    // Strategy-aware AuthPSK
    let AuthPskSealWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: AuthPskSealRequest) : Result<BaseSealResult, Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let encap = getKemEncap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadEnc = getAeadEncrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let (epk, shared1) = encap request.RecipientPublicKey
                let sharedAuth = Crypto.deriveSharedSecret request.SenderPrivateKey request.RecipientPublicKey
                let combined = Array.concat [ shared1; sharedAuth ]
                let prk = kdfExtract (Some request.Psk) combined
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                let ct = aeadEnc key nonce request.Aad request.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with _ -> Error (Hpke.Core.NotImplemented "HPKE AuthPsk seal with strategies")

    let AuthPskOpenWithStrategies kem kdf aead (custom: HpkeStrategies option) (request: AuthPskOpenRequest) : Result<byte[], Hpke.Core.HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error e -> Error e
        | Ok _ ->
            try
                let decap = getKemDecap custom
                let kdfExtract = getKdfExtract custom
                let kdfExpand = getKdfExpand custom
                let aeadDec = getAeadDecrypt custom
                let keySize = getAeadKeySize custom
                let nonceSize = getAeadNonceSize custom

                let shared1 = decap request.RecipientPrivateKey request.EncappedKey
                let sharedAuth = Crypto.deriveSharedSecret request.SenderPublicKey request.RecipientPrivateKey
                let combined = Array.concat [ shared1; sharedAuth ]
                let prk = kdfExtract (Some request.Psk) combined
                let key = kdfExpand prk request.Info keySize
                let nonceInfo = Array.append request.Info [|0uy|]
                let nonce = kdfExpand prk nonceInfo nonceSize
                match aeadDec key nonce request.Aad request.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (Hpke.Core.InvalidArgument("Ciphertext", "decryption failed"))
            with _ -> Error (Hpke.Core.NotImplemented "HPKE AuthPsk open with strategies")
