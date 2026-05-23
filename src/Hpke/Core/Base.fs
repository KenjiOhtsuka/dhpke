namespace Hpke.Core

module Base =
    let private supportedSuiteMessage = "Only the P-256, P-384, or P-521 / HKDF-SHA256, HKDF-SHA384, or HKDF-SHA512 / AES-128-GCM or AES-256-GCM suites are currently implemented"

    let private validateSealRequest (request: BaseSealRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", supportedSuiteMessage))
            else
                match RequestValidation.requireNotEmptyBytes "RecipientPublicKey" request.RecipientPublicKey with
                | Error error -> Error error
                | Ok recipientPublicKey ->
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
                                    Info = info
                                    Aad = aad
                                    Plaintext = plaintext
                                }

    let Seal (request: BaseSealRequest) : Result<BaseSealResult, HpkeError> =
        match validateSealRequest request with
        | Error error -> Error error
        | Ok state ->
            try
                let (esk, epk) = Crypto.generateKeyPairForKem state.Suite.Kem
                let shared1 = Crypto.deriveSharedSecretForKem state.Suite.Kem esk state.RecipientPublicKey
                let hashAlgorithm = Suites.kdfHash state.Suite.Kdf
                let prk = Crypto.hkdfExtractWithHash hashAlgorithm null shared1
                let key = Crypto.hkdfExpandWithHash hashAlgorithm prk state.Info (Suites.aeadKeySize state.Suite.Aead)
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                let ct = Crypto.aesGcmEncrypt key nonce state.Aad state.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with
            | _ -> Error (NotImplemented "HPKE Base seal")

    let Open (request: BaseOpenRequest) : Result<byte[], HpkeError> =
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
                        match RequestValidation.requireNotNull "Info" request.Info with
                        | Error error -> Error error
                        | Ok info ->
                            match RequestValidation.requireNotNull "Aad" request.Aad with
                            | Error error -> Error error
                            | Ok aad ->
                                match RequestValidation.requireNotNull "Ciphertext" request.Ciphertext with
                                | Error error -> Error error
                                | Ok ciphertext ->
                                    try
                                        let shared1 = Crypto.deriveSharedSecretForKem suite.Kem recipientPrivateKey encappedKey
                                        let hashAlgorithm = Suites.kdfHash suite.Kdf
                                        let prk = Crypto.hkdfExtractWithHash hashAlgorithm null shared1
                                        let key = Crypto.hkdfExpandWithHash hashAlgorithm prk info (Suites.aeadKeySize suite.Aead)
                                        let nonceInfo = Array.append info [|0uy|]
                                        let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                                        match Crypto.aesGcmDecrypt key nonce aad ciphertext with
                                        | Some pt -> Ok pt
                                        | None -> Error (InvalidArgument("Ciphertext", "decryption failed"))
                                    with
                                    | _ -> Error (NotImplemented "HPKE Base open")