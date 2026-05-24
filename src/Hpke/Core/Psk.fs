namespace Hpke.Core

module Psk =
    let private supportedSuiteMessage = "Only the P-256, X25519, P-384, or P-521 / HKDF-SHA256, HKDF-SHA384, or HKDF-SHA512 / AES-128-GCM or AES-256-GCM suites are currently implemented"

    type private PskSealState = {
        Suite: HpkeSuite
        RecipientPublicKey: byte[]
        Psk: byte[]
        PskId: byte[]
        Info: byte[]
        Aad: byte[]
        Plaintext: byte[]
    }

    type private PskOpenState = {
        Suite: HpkeSuite
        RecipientPrivateKey: byte[]
        EncappedKey: byte[]
        Psk: byte[]
        PskId: byte[]
        Info: byte[]
        Aad: byte[]
        Ciphertext: byte[]
    }

    let private validateSealRequest (request: PskSealRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", supportedSuiteMessage))
            else
                match RequestValidation.requireNotEmptyBytes "RecipientPublicKey" request.RecipientPublicKey with
                | Error error -> Error error
                | Ok recipientPublicKey ->
                    match RequestValidation.requireNotEmptyBytes "Psk" request.Psk with
                    | Error error -> Error error
                    | Ok psk ->
                        match RequestValidation.requireNotNull "PskId" request.PskId with
                        | Error error -> Error error
                        | Ok pskId ->
                            match RequestValidation.requireNotNull "Plaintext" request.Plaintext with
                            | Error error -> Error error
                            | Ok plaintext ->
                                match RequestValidation.requireNotNull "Info" request.Info with
                                | Error error -> Error error
                                | Ok info ->
                                    match RequestValidation.requireNotNull "Aad" request.Aad with
                                    | Error error -> Error error
                                    | Ok aad ->
                                        Ok {
                                            Suite = suite
                                            RecipientPublicKey = recipientPublicKey
                                            Psk = psk
                                            PskId = pskId
                                            Info = info
                                            Aad = aad
                                            Plaintext = plaintext
                                        }

    let private validateOpenRequest (request: PskOpenRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", supportedSuiteMessage))
            else
                match RequestValidation.requireNotEmptyBytes "RecipientPrivateKey" request.RecipientPrivateKey with
                | Error error -> Error error
                | Ok recipientPrivateKey ->
                    match RequestValidation.requireNotEmptyBytes "EncappedKey" request.EncappedKey with
                    | Error error -> Error error
                    | Ok encappedKey ->
                        match RequestValidation.requireNotEmptyBytes "Psk" request.Psk with
                        | Error error -> Error error
                        | Ok psk ->
                            match RequestValidation.requireNotNull "PskId" request.PskId with
                            | Error error -> Error error
                            | Ok pskId ->
                                match RequestValidation.requireNotNull "Ciphertext" request.Ciphertext with
                                | Error error -> Error error
                                | Ok ciphertext ->
                                    match RequestValidation.requireNotNull "Info" request.Info with
                                    | Error error -> Error error
                                    | Ok info ->
                                        match RequestValidation.requireNotNull "Aad" request.Aad with
                                        | Error error -> Error error
                                        | Ok aad ->
                                            Ok {
                                                Suite = suite
                                                RecipientPrivateKey = recipientPrivateKey
                                                EncappedKey = encappedKey
                                                Psk = psk
                                                PskId = pskId
                                                Info = info
                                                Aad = aad
                                                Ciphertext = ciphertext
                                            }

    let Seal (request: PskSealRequest) : Result<BaseSealResult, HpkeError> =
        match validateSealRequest request with
        | Error error -> Error error
        | Ok state ->
            try
                // ephemeral key pair
                let (esk, epk) = Crypto.generateKeyPairForKem state.Suite.Kem
                // shared secret: ephemeral->recipient
                let shared1 = Crypto.deriveSharedSecretForKem state.Suite.Kem esk state.RecipientPublicKey
                let hashAlgorithm = Suites.kdfHash state.Suite.Kdf
                let prk = Crypto.hkdfExtractWithHash hashAlgorithm state.Psk shared1
                let key = Crypto.hkdfExpandWithHash hashAlgorithm prk state.Info (Suites.aeadKeySize state.Suite.Aead)
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                let ct = Crypto.aesGcmEncrypt key nonce state.Aad state.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with
            | _ -> Error (NotImplemented "HPKE PSK seal")

    let Open (request: PskOpenRequest) : Result<byte[], HpkeError> =
        match validateOpenRequest request with
        | Error error -> Error error
        | Ok state ->
            try
                let shared1 = Crypto.deriveSharedSecretForKem state.Suite.Kem state.RecipientPrivateKey state.EncappedKey
                let hashAlgorithm = Suites.kdfHash state.Suite.Kdf
                let prk = Crypto.hkdfExtractWithHash hashAlgorithm state.Psk shared1
                let key = Crypto.hkdfExpandWithHash hashAlgorithm prk state.Info (Suites.aeadKeySize state.Suite.Aead)
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                match Crypto.aesGcmDecrypt key nonce state.Aad state.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (InvalidArgument("Ciphertext", "decryption failed"))
            with
            | _ -> Error (NotImplemented "HPKE PSK open")