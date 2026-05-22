module BaseTests

open Hpke.Core
open Xunit

[<Fact>]
let ``base seal and open roundtrip`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 9uy; 10uy |]
    }

    match Base.Seal sealReq with
    | Error _ -> failwith "Base.Seal not implemented"
    | Ok res ->
        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = res.Ciphertext
        }

        match Base.Open openReq with
        | Error e -> failwithf "Open failed: %A" e
        | Ok pt -> Assert.Equal<byte[]>([| 9uy; 10uy |], pt)

[<Fact>]
let ``base open fails when ciphertext tampered`` () =
    let suite = {
        Kem = DhKemP256HkdfSha256
        Kdf = HkdfSha256
        Aead = Aes128Gcm
    }

    let (recipientSk, recipientPk) = Hpke.Core.Crypto.generateEcdhP256KeyPair()

    let sealReq = {
        Suite = suite
        RecipientPublicKey = recipientPk
        Info = [||]
        Aad = [||]
        Plaintext = [| 9uy; 10uy |]
    }

    match Base.Seal sealReq with
    | Error _ -> failwith "Base.Seal not implemented"
    | Ok res ->
        let tampered = Array.copy res.Ciphertext
        if tampered.Length > 0 then tampered.[tampered.Length-1] <- tampered.[tampered.Length-1] ^^^ 0xFFuy

        let openReq = {
            Suite = suite
            RecipientPrivateKey = recipientSk
            EncappedKey = res.EncappedKey
            Info = [||]
            Aad = [||]
            Ciphertext = tampered
        }

        match Base.Open openReq with
        | Ok _ -> failwith "Open succeeded but should have failed on tampered ciphertext"
        | Error (InvalidArgument(name, _)) -> Assert.Equal("Ciphertext", name)
        | Error e -> failwithf "Unexpected error: %A" e
