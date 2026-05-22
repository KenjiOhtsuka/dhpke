module AuthTests

open Hpke.Core
open Xunit

[<Fact>]
let ``auth seal and open roundtrip`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (senderSk, senderPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        SenderPrivateKey = senderSk
        Info = [||]
        Aad = [||]
        Plaintext = [| 5uy; 6uy |]
    }

    match Auth.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            SenderPublicKey = senderPk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Auth.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 5uy; 6uy |], pt)


[<Fact>]
let ``auth open fails when ciphertext tampered`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()
    let (senderSk, senderPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        SenderPrivateKey = senderSk
        Info = [||]
        Aad = [||]
        Plaintext = [| 5uy; 6uy |]
    }

    match Auth.Seal sealReq with
    | Error e -> failwithf "Seal failed: %A" e
    | Ok res ->
        let tampered = Array.copy res.Ciphertext
        if tampered.Length > 0 then tampered.[0] <- tampered.[0] ^^^ 0xFFuy

        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            SenderPublicKey = senderPk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = tampered
        }

        match Auth.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed on tampered ciphertext"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e
