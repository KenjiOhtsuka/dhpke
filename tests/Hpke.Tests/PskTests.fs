module PskTests

open Hpke.Core
open Xunit

[<Fact>]
let ``psk seal and open roundtrip`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Plaintext = [| 7uy; 8uy |]
    }

    match Psk.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Psk.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 7uy; 8uy |], pt)


[<Fact>]
let ``psk open fails when ciphertext tampered`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let psk = [| 1uy; 2uy; 3uy |]
    let pskId = [| 9uy |]

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Psk = psk
        PskId = pskId
        Info = [||]
        Aad = [||]
        Plaintext = [| 7uy; 8uy |]
    }

    match Psk.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let tampered = Array.copy res.Ciphertext
        if tampered.Length > 0 then tampered.[tampered.Length-1] <- tampered.[tampered.Length-1] ^^^ 0xFFuy

        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Psk = psk
            PskId = pskId
            Info = [||]
            Aad = [||]
            Ciphertext = tampered
        }

        match Psk.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed on tampered ciphertext"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e
