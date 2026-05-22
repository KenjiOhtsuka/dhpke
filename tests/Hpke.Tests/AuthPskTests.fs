module AuthPskTests

open Hpke.Core
open Xunit

[<Fact>]
let ``auth psk seal and open roundtrip`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    // generate keys
    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (senderSk, senderPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        SenderPrivateKey = senderSk
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Plaintext = [| 42uy; 43uy |]
    }

    match AuthPsk.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            SenderPublicKey = senderPk
            EncappedKey = res.EncappedKey
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match AuthPsk.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 42uy; 43uy |], pt)


[<Fact>]
let ``auth psk open fails when ciphertext tampered`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (senderSk, senderPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        SenderPrivateKey = senderSk
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Plaintext = [| 42uy; 43uy |]
    }

    match AuthPsk.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        // tamper ciphertext
        let tampered = Array.copy res.Ciphertext
        if tampered.Length > 0 then tampered.[0] <- tampered.[0] ^^^ 0xFFuy

        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            SenderPublicKey = senderPk
            EncappedKey = res.EncappedKey
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Ciphertext = tampered
        }

        match AuthPsk.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed on tampered ciphertext"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e


[<Fact>]
let ``auth psk open fails with wrong recipient private key`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (senderSk, senderPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (otherSk, _) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        SenderPrivateKey = senderSk
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Plaintext = [| 42uy; 43uy |]
    }

    match AuthPsk.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = otherSk
            SenderPublicKey = senderPk
            EncappedKey = res.EncappedKey
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match AuthPsk.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed with wrong recipient key"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e


[<Fact>]
let ``auth psk seal validation fails for empty recipient public key`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let request = {
        Suite = suite
        RecipientPublicKey = [||]
        SenderPrivateKey = [| 1uy |]
        Psk = [| 1uy |]
        PskId = [| 2uy |]
        Info = [||]
        Aad = [||]
        Plaintext = [| 42uy |]
    }

    match AuthPsk.Seal request with
    | Error (InvalidLength(name, _, len)) ->
        Assert.Equal("RecipientPublicKey", name)
        Assert.Equal(0, len)
    | result -> failwithf "Unexpected result: %A" result