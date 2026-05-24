namespace Hpke.Core

module Auth =
    let private supportedSuiteMessage = "Only the P-256, X25519, P-384, or P-521 / HKDF-SHA256, HKDF-SHA384, or HKDF-SHA512 / AES-128-GCM or AES-256-GCM suites are currently implemented"

    type private AuthSealState = {
        Suite: HpkeSuite
        RecipientPublicKey: byte[]
        SenderPrivateKey: byte[]
        Info: byte[]
        Aad: byte[]
        Plaintext: byte[]
    }

    type private AuthOpenState = {
        Suite: HpkeSuite
        RecipientPrivateKey: byte[]
        SenderPublicKey: byte[]
        EncappedKey: byte[]
        Info: byte[]
        Aad: byte[]
        Ciphertext: byte[]
    }

    let private validateSealRequest (request: AuthSealRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", supportedSuiteMessage))
            else
                match RequestValidation.requireNotEmptyBytes "RecipientPublicKey" request.RecipientPublicKey with
                | Error error -> Error error
                | Ok recipientPublicKey ->
                    match RequestValidation.requireNotEmptyBytes "SenderPrivateKey" request.SenderPrivateKey with
                    | Error error -> Error error
                    | Ok senderPrivateKey ->
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
                                        SenderPrivateKey = senderPrivateKey
                                        Info = info
                                        Aad = aad
                                        Plaintext = plaintext
                                    }

    let private validateOpenRequest (request: AuthOpenRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", supportedSuiteMessage))
            else
                match RequestValidation.requireNotEmptyBytes "RecipientPrivateKey" request.RecipientPrivateKey with
                | Error error -> Error error
                | Ok recipientPrivateKey ->
                    match RequestValidation.requireNotEmptyBytes "SenderPublicKey" request.SenderPublicKey with
                    | Error error -> Error error
                    | Ok senderPublicKey ->
                        match RequestValidation.requireNotEmptyBytes "EncappedKey" request.EncappedKey with
                        | Error error -> Error error
                        | Ok encappedKey ->
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
                                            SenderPublicKey = senderPublicKey
                                            EncappedKey = encappedKey
                                            Info = info
                                            Aad = aad
                                            Ciphertext = ciphertext
                                        }

    let Seal (request: AuthSealRequest) : Result<BaseSealResult, HpkeError> =
        match validateSealRequest request with
        | Error error -> Error error
        | Ok state ->
            try
                let (esk, epk) = Crypto.generateKeyPairForKem state.Suite.Kem
                let shared1 = Crypto.deriveSharedSecretForKem state.Suite.Kem esk state.RecipientPublicKey
                let shared2 = Crypto.deriveSharedSecretForKem state.Suite.Kem state.SenderPrivateKey state.RecipientPublicKey
                let hashAlgorithm = Suites.kdfHash state.Suite.Kdf
                let prk = Crypto.hkdfExtractWithHash hashAlgorithm null (Array.concat [shared1; shared2])
                let key = Crypto.hkdfExpandWithHash hashAlgorithm prk state.Info (Suites.aeadKeySize state.Suite.Aead)
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                let ct = Crypto.aesGcmEncrypt key nonce state.Aad state.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with
            | _ -> Error (NotImplemented "HPKE Auth seal")

    let Open (request: AuthOpenRequest) : Result<byte[], HpkeError> =
        match validateOpenRequest request with
        | Error error -> Error error
        | Ok state ->
            try
                let shared1 = Crypto.deriveSharedSecretForKem state.Suite.Kem state.RecipientPrivateKey state.EncappedKey
                let shared2 = Crypto.deriveSharedSecretForKem state.Suite.Kem state.RecipientPrivateKey state.SenderPublicKey
                let hashAlgorithm = Suites.kdfHash state.Suite.Kdf
                let prk = Crypto.hkdfExtractWithHash hashAlgorithm null (Array.concat [shared1; shared2])
                let key = Crypto.hkdfExpandWithHash hashAlgorithm prk state.Info (Suites.aeadKeySize state.Suite.Aead)
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpandWithHash hashAlgorithm prk nonceInfo 12
                match Crypto.aesGcmDecrypt key nonce state.Aad state.Ciphertext with
                | Some pt -> Ok pt
                | None -> Error (InvalidArgument("Ciphertext", "decryption failed"))
            with
            | _ -> Error (NotImplemented "HPKE Auth open")