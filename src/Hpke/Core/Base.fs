namespace Hpke.Core

module Base =
    let private validateSealRequest (request: BaseSealRequest) =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", "Only the P-256 / HKDF-SHA256 / AES-128-GCM suite is currently implemented"))
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
                let (esk, epk) = Crypto.generateEcdhP256KeyPair()
                let shared1 = Crypto.deriveSharedSecret esk state.RecipientPublicKey
                let prk = Crypto.hkdfExtract null shared1
                let key = Crypto.hkdfExpand prk state.Info 32
                let nonceInfo = Array.append state.Info [|0uy|]
                let nonce = Crypto.hkdfExpand prk nonceInfo 12
                let ct = Crypto.aesGcmEncrypt key nonce state.Aad state.Plaintext
                Ok { EncappedKey = epk; Ciphertext = ct }
            with
            | _ -> Error (NotImplemented "HPKE Base seal")

    let Open (request: BaseOpenRequest) : Result<byte[], HpkeError> =
        match RequestValidation.requireNotNull "Suite" request.Suite with
        | Error error -> Error error
        | Ok suite ->
            if not (Suites.isSupportedSuite suite) then
                Error (InvalidArgument("Suite", "Only the P-256 / HKDF-SHA256 / AES-128-GCM suite is currently implemented"))
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
                                        let shared1 = Crypto.deriveSharedSecret recipientPrivateKey encappedKey
                                        let prk = Crypto.hkdfExtract null shared1
                                        let key = Crypto.hkdfExpand prk info 32
                                        let nonceInfo = Array.append info [|0uy|]
                                        let nonce = Crypto.hkdfExpand prk nonceInfo 12
                                        match Crypto.aesGcmDecrypt key nonce aad ciphertext with
                                        | Some pt -> Ok pt
                                        | None -> Error (InvalidArgument("Ciphertext", "decryption failed"))
                                    with
                                    | _ -> Error (NotImplemented "HPKE Base open")